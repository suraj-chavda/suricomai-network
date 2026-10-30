// SPDX-License-Identifier: LicenseRef-SuriComAI-Proprietary
pragma solidity 0.8.28;

/// @notice Minimal ERC-20 surface this contract uses.
interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title SuriComAIEscrow
/// @notice Holds a user's payment and a worker's bond for one inference job and releases them
///         when a threshold of a fixed committee signs the outcome, or returns them after
///         expiry with no help from anyone. Immutable: no key can move user funds, change a
///         rule, change a fee rate, or change the committee. The escrow contract specification has the full rules.
/// @dev A job has one itemized price (see `quote`): the worker's price plus a protocol fee, an
///      attestation fee and at most one relay fee. The user locks that total and nothing else is
///      ever taken. A job that is not delivered refunds every unit. All payouts are pulls.
///      Nothing here reads a prompt, an answer, or a proof. The committee is trusted and is not
///      bonded on-chain in this version.
contract SuriComAIEscrow {
    // ---------------------------------------------------------------- types

    enum Phase {
        None,
        Locked,
        Bonded,
        Paid,
        Expired,
        Slashed
    }

    /// @dev Faults a committee may attest. Zero is not a fault.
    enum Fault {
        None,
        MeasurementRejected,
        MissingGpuEvidence,
        BadQuote,
        InvalidProof
    }

    struct Job {
        address user;
        uint64 expiry;
        Phase phase;
        uint128 cap;
        uint128 bondRequired;
        address worker;
        address payee;
        bytes32 contractHash;
        bytes32 receiptKey;
    }

    /// @dev The whole price of one job. `total` is what the user locks.
    struct Quote {
        uint256 price;
        uint256 protocol;
        uint256 attestation;
        uint256 relayMax;
        uint256 total;
    }

    // ------------------------------------------------------------- constants

    /// @dev Smallest worker price. Below it the fixed attestation line would be most of the cost.
    uint256 public constant MIN_PRICE = 10_000;
    uint256 public constant MAX_TTL = 1 days;
    uint256 public constant MAX_COMMITTEE = 32;
    /// @dev Hard caps. No deployment can be built with a line past any of them.
    uint256 public constant MAX_PROTOCOL_BPS = 300;
    uint256 public constant MAX_ATTESTATION_BPS = 300;
    uint256 public constant MAX_RELAY_BPS = 300;
    uint256 public constant MAX_ATTESTATION_MIN = 100_000;
    uint256 private constant BPS = 10_000;
    /// @dev Where the seized part of a slashed bond goes. Nobody can withdraw from it, so nobody
    ///      profits from a slash, including the protocol fee recipient and the committee.
    address public constant BURN = address(0xdEaD);
    /// @dev Upper bound of a canonical ECDSA `s` value (half the curve order).
    uint256 private constant HALF_ORDER = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant SETTLE_TYPEHASH = keccak256(
        "Settle(bytes32 jobId,bytes32 contractHash,address worker,bytes32 receiptKey,uint256 amountDue,address relayPayee)"
    );
    bytes32 public constant SLASH_TYPEHASH = keccak256(
        "Slash(bytes32 jobId,bytes32 contractHash,address worker,bytes32 receiptKey,uint8 fault,bytes32 evidence)"
    );

    // ------------------------------------------------------------- immutables

    IERC20 public immutable token;
    address public immutable protocolRecipient;
    address public immutable guardian;
    uint256 public immutable threshold;
    uint256 public immutable committeeSize;
    uint256 public immutable userSlashBps;
    uint256 public immutable protocolBps;
    uint256 public immutable attestationBps;
    uint256 public immutable attestationMin;
    uint256 public immutable relayBps;
    uint256 public immutable launchTime;
    uint256 public immutable startCap;
    uint256 public immutable capStep;
    uint256 public immutable capPeriod;
    uint256 public immutable maxCap;
    uint256 public immutable userCap;
    uint256 private immutable _cachedChainId;
    bytes32 private immutable _cachedDomainSeparator;

    // ---------------------------------------------------------------- storage

    mapping(bytes32 => Job) public jobs;
    mapping(address => bool) public isMember;
    mapping(address => uint256) private _claimable;
    mapping(address => uint256) private _committeeSeen;
    mapping(address => uint256) public lockedByUser;
    /// @dev The worker price quoted when each job was locked.
    mapping(bytes32 => uint128) public priceOf;

    /// @dev Cumulative amount owed to each committee member from the committee share.
    uint256 public committeeIndex;
    /// @dev Attestation fee that did not divide evenly among members. It carries into the next
    ///      settlement, so no unit of the committee line is ever kept by anyone else.
    uint256 public committeeCarry;
    uint256 public lockedGlobal;
    uint256 public heldFees;
    uint256 public heldBonds;
    /// @dev Sum of every balance an account can still withdraw, including the committee pool.
    uint256 public totalClaimable;
    bool public paused;

    uint256 private _entered = 1;

    // ----------------------------------------------------------------- events

    event JobLocked(
        bytes32 indexed jobId,
        address indexed user,
        address indexed worker,
        bytes32 contractHash,
        uint256 price,
        uint256 total,
        uint256 bondRequired,
        uint64 expiry
    );
    event BondPosted(bytes32 indexed jobId, address indexed worker, address payee, bytes32 receiptKey);
    event Settled(bytes32 indexed jobId, uint256 amountDue, address relayPayee);
    event Slashed(bytes32 indexed jobId, Fault fault, bytes32 evidence);
    event Expired(bytes32 indexed jobId);
    event Withdrawn(address indexed account, address indexed to, uint256 amount);
    event PauseChanged(bool paused);

    // ----------------------------------------------------------------- errors

    error Reentrancy();
    error Paused();
    error NotGuardian();
    error ZeroValue();
    error PriceTooSmall();
    error FeeOverflow();
    error OverMax();
    error BadExpiry();
    error TtlTooLong();
    error JobExists();
    error UnknownJob();
    error BadPhase();
    error NotExpired();
    error AlreadyExpired();
    error NotWorker();
    error GlobalCap();
    error UserCapExceeded();
    error BadFault();
    error NoEvidence();
    error BadSignatures();
    error TransferFailed();
    error WrongAmountReceived();
    error NothingToWithdraw();
    error TooLarge();
    error BadConfig();

    // ------------------------------------------------------------ constructor

    struct Config {
        address token;
        address[] committee;
        uint256 threshold;
        address protocolRecipient;
        address guardian;
        uint256 userSlashBps;
        uint256 protocolBps;
        uint256 attestationBps;
        uint256 attestationMin;
        uint256 relayBps;
        uint256 startCap;
        uint256 capStep;
        uint256 capPeriod;
        uint256 maxCap;
        uint256 userCap;
    }

    constructor(Config memory c) {
        uint256 n = c.committee.length;
        if (n == 0 || n > MAX_COMMITTEE) revert BadConfig();
        if (c.threshold <= n / 2 || c.threshold > n) revert BadConfig();
        if (c.token.code.length == 0) revert BadConfig();
        if (c.protocolRecipient == address(0) || c.guardian == address(0)) revert BadConfig();
        if (c.userSlashBps > BPS) revert BadConfig();
        if (
            c.protocolBps > MAX_PROTOCOL_BPS || c.attestationBps > MAX_ATTESTATION_BPS || c.relayBps > MAX_RELAY_BPS
                || c.attestationMin > MAX_ATTESTATION_MIN
        ) revert BadConfig();
        if (c.capPeriod == 0 || c.startCap > c.maxCap || c.userCap == 0) revert BadConfig();
        address last;
        for (uint256 i = 0; i < n; i++) {
            address member = c.committee[i];
            if (member <= last) revert BadConfig();
            isMember[member] = true;
            last = member;
        }
        token = IERC20(c.token);
        protocolRecipient = c.protocolRecipient;
        guardian = c.guardian;
        threshold = c.threshold;
        committeeSize = n;
        userSlashBps = c.userSlashBps;
        protocolBps = c.protocolBps;
        attestationBps = c.attestationBps;
        attestationMin = c.attestationMin;
        relayBps = c.relayBps;
        launchTime = block.timestamp;
        startCap = c.startCap;
        capStep = c.capStep;
        capPeriod = c.capPeriod;
        maxCap = c.maxCap;
        userCap = c.userCap;
        _cachedChainId = block.chainid;
        _cachedDomainSeparator = _buildDomainSeparator();
    }

    // --------------------------------------------------------------- modifiers

    modifier nonReentrant() {
        if (_entered != 1) revert Reentrancy();
        _entered = 2;
        _;
        _entered = 1;
    }

    // -------------------------------------------------------------- user calls

    /// @notice Lock the whole price of one job and pin the worker who may bond it.
    /// @param salt Chosen by the user. The job id commits to the caller, so nobody else can
    ///        lock this id.
    /// @param contractHash BLAKE3 hash of the sealed job header. Opaque to this contract.
    /// @param price What the worker is paid. The protocol, attestation and relay lines are added
    ///        on top by `quote`, and the user locks the total.
    /// @param maxTotal The most the user agrees to lock. If the quote is higher, this reverts, so
    ///        a screen that showed a lower number cannot cost the user more.
    function lock(
        bytes32 salt,
        bytes32 contractHash,
        uint128 price,
        uint128 maxTotal,
        uint64 expiry,
        uint128 bondRequired,
        address worker
    ) external nonReentrant returns (bytes32 jobId) {
        if (paused) revert Paused();
        if (contractHash == bytes32(0) || worker == address(0)) revert ZeroValue();
        Quote memory q = quote(price);
        if (q.total > maxTotal) revert OverMax();
        uint128 cap = uint128(q.total);
        if (expiry <= block.timestamp) revert BadExpiry();
        if (expiry - block.timestamp > MAX_TTL) revert TtlTooLong();
        jobId = keccak256(abi.encode(msg.sender, salt));
        if (jobs[jobId].phase != Phase.None) revert JobExists();

        uint256 reserved = uint256(cap) + uint256(bondRequired);
        if (lockedGlobal + reserved > capAt(block.timestamp)) revert GlobalCap();
        if (lockedByUser[msg.sender] + cap > userCap) revert UserCapExceeded();

        jobs[jobId] = Job({
            user: msg.sender,
            expiry: expiry,
            phase: Phase.Locked,
            cap: cap,
            bondRequired: bondRequired,
            worker: worker,
            payee: address(0),
            contractHash: contractHash,
            receiptKey: bytes32(0)
        });
        priceOf[jobId] = price;
        lockedGlobal += reserved;
        lockedByUser[msg.sender] += cap;
        heldFees += cap;

        _pullExact(msg.sender, cap);
        emit JobLocked(jobId, msg.sender, worker, contractHash, price, cap, bondRequired, expiry);
    }

    // ------------------------------------------------------------ worker calls

    /// @notice The pinned worker posts the bond and records who is paid and which receipt key
    ///         the committee must attest for.
    function postBond(bytes32 jobId, address payee, bytes32 receiptKey) external nonReentrant {
        Job storage job = jobs[jobId];
        if (job.phase != Phase.Locked) revert BadPhase();
        if (msg.sender != job.worker) revert NotWorker();
        if (block.timestamp >= job.expiry) revert AlreadyExpired();
        if (payee == address(0) || receiptKey == bytes32(0)) revert ZeroValue();

        job.payee = payee;
        job.receiptKey = receiptKey;
        job.phase = Phase.Bonded;
        heldBonds += job.bondRequired;

        if (job.bondRequired > 0) _pullExact(msg.sender, job.bondRequired);
        emit BondPosted(jobId, msg.sender, payee, receiptKey);
    }

    // -------------------------------------------------------- settlement calls

    /// @notice Pay a job. `sigs` is the concatenation of committee signatures (65 bytes each,
    ///         signers strictly increasing by address) over the Settle typed data. The amount the
    ///         committee signs is the quoted price, so it cannot attest a different amount.
    /// @dev Every unit of the locked total goes to exactly one place: the worker gets the price,
    ///      the committee the attestation line, the protocol recipient the protocol line, the
    ///      relay its line when one carried the job, and the user whatever is left of the relay
    ///      line. The parts always sum to the total.
    function settle(bytes32 jobId, address relayPayee, bytes calldata sigs) external nonReentrant {
        Job storage job = jobs[jobId];
        if (job.phase != Phase.Bonded) revert BadPhase();
        if (block.timestamp >= job.expiry) revert AlreadyExpired();
        Quote memory q = quote(priceOf[jobId]);

        bytes32 digest = _digest(
            keccak256(
                abi.encode(SETTLE_TYPEHASH, jobId, job.contractHash, job.worker, job.receiptKey, q.price, relayPayee)
            )
        );
        _requireCommittee(digest, sigs);

        job.phase = Phase.Paid;
        _release(job, true);

        // The committee line is shared equally. What does not divide evenly carries forward.
        uint256 pool = q.attestation + committeeCarry;
        uint256 perMember = pool / committeeSize;
        uint256 pooled = perMember * committeeSize;
        committeeCarry = pool - pooled;
        if (pooled > 0) {
            committeeIndex += perMember;
            totalClaimable += pooled;
        }
        // Whatever of the relay line is not paid to a relay goes back to the user.
        uint256 relayPaid = relayPayee == address(0) ? 0 : q.relayMax;
        _credit(relayPayee, relayPaid);
        _credit(job.payee, q.price);
        _credit(protocolRecipient, q.protocol);
        _credit(job.user, q.relayMax - relayPaid);
        _credit(job.worker, job.bondRequired);

        emit Settled(jobId, q.price, relayPayee);
    }

    /// @notice Refund the user and seize the bond because the committee attests a fault.
    function slash(bytes32 jobId, Fault fault, bytes32 evidence, bytes calldata sigs) external nonReentrant {
        Job storage job = jobs[jobId];
        if (job.phase != Phase.Locked && job.phase != Phase.Bonded) revert BadPhase();
        if (fault == Fault.None || uint8(fault) > uint8(Fault.InvalidProof)) revert BadFault();
        if (evidence == bytes32(0)) revert NoEvidence();

        bytes32 digest = _digest(
            keccak256(
                abi.encode(SLASH_TYPEHASH, jobId, job.contractHash, job.worker, job.receiptKey, uint8(fault), evidence)
            )
        );
        _requireCommittee(digest, sigs);

        bool bonded = job.phase == Phase.Bonded;
        job.phase = Phase.Slashed;
        _release(job, bonded);

        _credit(job.user, job.cap);
        if (bonded && job.bondRequired > 0) {
            uint256 toUser = (uint256(job.bondRequired) * userSlashBps) / BPS;
            _credit(job.user, toUser);
            _credit(BURN, uint256(job.bondRequired) - toUser);
        }
        emit Slashed(jobId, fault, evidence);
    }

    /// @notice After expiry, return the fee and any bond to the user. Needs nobody else.
    function expire(bytes32 jobId) external nonReentrant {
        Job storage job = jobs[jobId];
        if (job.phase != Phase.Locked && job.phase != Phase.Bonded) revert BadPhase();
        if (block.timestamp < job.expiry) revert NotExpired();

        bool bonded = job.phase == Phase.Bonded;
        job.phase = Phase.Expired;
        _release(job, bonded);

        _credit(job.user, job.cap);
        if (bonded) _credit(job.user, job.bondRequired);
        emit Expired(jobId);
    }

    // ---------------------------------------------------------------- withdraw

    /// @notice Pay the caller's whole balance (and any committee share) to `to`.
    function withdraw(address to) external nonReentrant returns (uint256 amount) {
        if (to == address(0)) revert ZeroValue();
        amount = _claimable[msg.sender];
        if (amount > 0) _claimable[msg.sender] = 0;
        if (isMember[msg.sender]) {
            uint256 owed = committeeIndex - _committeeSeen[msg.sender];
            if (owed > 0) {
                _committeeSeen[msg.sender] = committeeIndex;
                amount += owed;
            }
        }
        if (amount == 0) revert NothingToWithdraw();
        totalClaimable -= amount;
        _safeTransfer(to, amount);
        emit Withdrawn(msg.sender, to, amount);
    }

    // ---------------------------------------------------------------- guardian

    /// @notice Stop new locks. Exits, settlement, and withdrawals keep working.
    function pause() external {
        if (msg.sender != guardian) revert NotGuardian();
        paused = true;
        emit PauseChanged(true);
    }

    function unpause() external {
        if (msg.sender != guardian) revert NotGuardian();
        paused = false;
        emit PauseChanged(false);
    }

    // ------------------------------------------------------------------- views

    /// @notice Balance `account` can withdraw now, including a committee member's share.
    function claimableOf(address account) external view returns (uint256 amount) {
        amount = _claimable[account];
        if (isMember[account]) amount += committeeIndex - _committeeSeen[account];
    }

    /// @notice The whole price of a job for a worker price, under this deployment's fixed rates.
    ///         Every charge line rounds up to the next unit. A price below the minimum, or a
    ///         total that does not fit in 64 bits, is refused.
    function quote(uint128 price) public view returns (Quote memory q) {
        if (price < MIN_PRICE) revert PriceTooSmall();
        q.price = price;
        q.protocol = _ceilBps(price, protocolBps);
        uint256 byRate = _ceilBps(price, attestationBps);
        q.attestation = byRate < attestationMin ? attestationMin : byRate;
        q.relayMax = _ceilBps(price, relayBps);
        q.total = uint256(price) + q.protocol + q.attestation + q.relayMax;
        if (q.total > type(uint64).max) revert FeeOverflow();
    }

    /// @notice Global cap on locked value at time `t`. Rises on a fixed schedule.
    function capAt(uint256 t) public view returns (uint256) {
        if (t <= launchTime || capStep == 0) return startCap < maxCap ? startCap : maxCap;
        uint256 steps = (t - launchTime) / capPeriod;
        if (steps > (maxCap - startCap) / capStep) return maxCap;
        return startCap + steps * capStep;
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        if (block.chainid == _cachedChainId) return _cachedDomainSeparator;
        return _buildDomainSeparator();
    }

    // ---------------------------------------------------------------- internals

    function _buildDomainSeparator() private view returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("SuriComAIEscrow"), keccak256("1"), block.chainid, address(this))
        );
    }

    function _digest(bytes32 structHash) private view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
    }

    /// @dev Require at least `threshold` valid, distinct committee signatures.
    function _requireCommittee(bytes32 digest, bytes calldata sigs) private view {
        uint256 len = sigs.length;
        if (len % 65 != 0) revert BadSignatures();
        uint256 count = len / 65;
        if (count < threshold || count > committeeSize) revert BadSignatures();
        address last;
        for (uint256 i = 0; i < count; i++) {
            uint256 o = i * 65;
            bytes32 r = bytes32(sigs[o:o + 32]);
            bytes32 s = bytes32(sigs[o + 32:o + 64]);
            uint8 v = uint8(sigs[o + 64]);
            if ((v != 27 && v != 28) || uint256(s) > HALF_ORDER) revert BadSignatures();
            address signer = ecrecover(digest, v, r, s);
            if (signer == address(0) || signer <= last || !isMember[signer]) revert BadSignatures();
            last = signer;
        }
    }

    /// @dev `ceil(x * bps / 10000)`. `x` is at most 128 bits and `bps` at most 300, so no overflow.
    function _ceilBps(uint256 x, uint256 bps) private pure returns (uint256) {
        return (x * bps + BPS - 1) / BPS;
    }

    function _credit(address account, uint256 amount) private {
        if (amount == 0) return;
        _claimable[account] += amount;
        totalClaimable += amount;
    }

    /// @dev Stop counting a job's money as held. `bonded` says whether the bond was posted.
    function _release(Job storage job, bool bonded) private {
        heldFees -= job.cap;
        if (bonded) heldBonds -= job.bondRequired;
        lockedGlobal -= uint256(job.cap) + uint256(job.bondRequired);
        lockedByUser[job.user] -= job.cap;
    }

    /// @dev Pull exactly `amount`. A token that takes a fee, or returns false, reverts.
    function _pullExact(address from, uint256 amount) private {
        uint256 before = token.balanceOf(address(this));
        (bool ok, bytes memory ret) =
            address(token).call(abi.encodeWithSelector(IERC20.transferFrom.selector, from, address(this), amount));
        if (!_succeeded(ok, ret)) revert TransferFailed();
        uint256 afterBalance = token.balanceOf(address(this));
        if (afterBalance < before || afterBalance - before != amount) revert WrongAmountReceived();
    }

    function _safeTransfer(address to, uint256 amount) private {
        (bool ok, bytes memory ret) = address(token).call(abi.encodeWithSelector(IERC20.transfer.selector, to, amount));
        if (!_succeeded(ok, ret)) revert TransferFailed();
    }

    /// @dev Accept a call that returned nothing (old tokens) or returned true.
    function _succeeded(bool ok, bytes memory ret) private pure returns (bool) {
        if (!ok) return false;
        if (ret.length == 0) return true;
        if (ret.length != 32) return false;
        return abi.decode(ret, (bool));
    }
}
