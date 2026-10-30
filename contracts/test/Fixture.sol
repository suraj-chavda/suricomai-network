// SPDX-License-Identifier: LicenseRef-SuriComAI-Proprietary
pragma solidity 0.8.28;

import {SuriComAIEscrow} from "../src/SuriComAIEscrow.sol";
import {Vm} from "./Vm.sol";
import {MockUSDC} from "./Mocks.sol";

/// @dev Shared setup. The EIP-712 digests are rebuilt here from the type strings in the spec,
///      not read from the contract, so a mistake in the contract cannot hide itself.
abstract contract Fixture {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 internal constant N = 5;
    uint256 internal constant T = 3;
    uint256 internal constant START = 1_000_000;
    uint256 internal constant BIG = 1e15;

    /// @dev The default schedule is 1 percent protocol, 1 percent attestation with a floor of
    ///      2000 units, and up to 1 percent relay. For a one dollar price (1_000_000 units) every
    ///      line is exactly 10_000.
    uint128 internal constant P = 1_000_000;
    uint256 internal constant PROTO = 10_000;
    uint256 internal constant ATT = 10_000;
    uint256 internal constant RLY = 10_000;
    uint256 internal constant TOTAL = 1_030_000;

    address internal constant USER = address(0xA11CE);
    address internal constant WORKER = address(0xB0B);
    address internal constant PAYEE = address(0xBEEF);
    address internal constant RELAY = address(0xDEAD00);
    address internal constant PROTOCOL = address(0x5E5E);
    address internal constant GUARDIAN = address(0x6A4D);
    address internal constant OTHER = address(0xC0FFEE);

    bytes32 internal constant CH = keccak256("contract hash");
    bytes32 internal constant KEY = keccak256("receipt key");

    uint256[] internal keys;
    address[] internal members;

    MockUSDC internal usdc;
    SuriComAIEscrow internal esc;

    function setUp() public virtual {
        vm.warp(START);
        for (uint256 i = 0; i < N; i++) {
            keys.push(i + 1);
            members.push(vm.addr(i + 1));
        }
        // Sort both arrays by address, ascending.
        for (uint256 i = 1; i < N; i++) {
            for (uint256 j = i; j > 0 && members[j] < members[j - 1]; j--) {
                (members[j], members[j - 1]) = (members[j - 1], members[j]);
                (keys[j], keys[j - 1]) = (keys[j - 1], keys[j]);
            }
        }
        usdc = new MockUSDC();
        esc = new SuriComAIEscrow(_config(address(usdc)));
        _fund(address(usdc), address(esc));
    }

    function _config(address token) internal view returns (SuriComAIEscrow.Config memory c) {
        c = SuriComAIEscrow.Config({
            token: token,
            committee: members,
            threshold: T,
            protocolRecipient: PROTOCOL,
            guardian: GUARDIAN,
            userSlashBps: 5_000,
            protocolBps: 100,
            attestationBps: 100,
            attestationMin: 2_000,
            relayBps: 100,
            startCap: BIG,
            capStep: 0,
            capPeriod: 1 days,
            maxCap: BIG,
            userCap: BIG
        });
    }

    function _fund(address token, address spender) internal {
        for (uint256 i = 0; i < 3; i++) {
            address who = i == 0 ? USER : (i == 1 ? WORKER : OTHER);
            MockUSDC(token).mint(who, 1e24);
            vm.prank(who);
            MockUSDC(token).approve(spender, type(uint256).max);
        }
    }

    // ------------------------------------------------------------- job helpers

    /// @dev Lock a job priced at `price`, agreeing to exactly the quoted total.
    function _lock(bytes32 salt, uint128 price, uint128 bond, uint64 ttl) internal returns (bytes32 id) {
        vm.prank(USER);
        id = esc.lock(salt, CH, price, uint128(esc.quote(price).total), uint64(block.timestamp + ttl), bond, WORKER);
    }

    function _bond(bytes32 id) internal {
        vm.prank(WORKER);
        esc.postBond(id, PAYEE, KEY);
    }

    function _bonded(bytes32 salt, uint128 price, uint128 bond) internal returns (bytes32 id) {
        id = _lock(salt, price, bond, 3600);
        _bond(id);
    }

    function _job(bytes32 id)
        internal
        view
        returns (
            address user,
            uint64 expiry,
            SuriComAIEscrow.Phase phase,
            uint128 cap,
            uint128 bondRequired,
            address worker,
            address payee,
            bytes32 ch,
            bytes32 key
        )
    {
        return esc.jobs(id);
    }

    function _phase(bytes32 id) internal view returns (SuriComAIEscrow.Phase p) {
        (,, p,,,,,,) = esc.jobs(id);
    }

    // ------------------------------------------------------------ signing

    function _domain(address verifying) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("SuriComAIEscrow"),
                keccak256("1"),
                block.chainid,
                verifying
            )
        );
    }

    function _settleDigest(bytes32 id, uint256 amountDue, address relay, address verifying)
        internal
        view
        returns (bytes32)
    {
        (,,,,, address worker,, bytes32 ch, bytes32 key) = esc.jobs(id);
        return _settleDigestFor(id, ch, worker, key, amountDue, relay, verifying);
    }

    function _settleDigestFor(
        bytes32 id,
        bytes32 ch,
        address worker,
        bytes32 key,
        uint256 amountDue,
        address relay,
        address verifying
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Settle(bytes32 jobId,bytes32 contractHash,address worker,bytes32 receiptKey,uint256 amountDue,address relayPayee)"
                ),
                id,
                ch,
                worker,
                key,
                amountDue,
                relay
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", _domain(verifying), structHash));
    }

    function _slashDigest(bytes32 id, uint8 fault, bytes32 evidence) internal view returns (bytes32) {
        (,,,,, address worker,, bytes32 ch, bytes32 key) = esc.jobs(id);
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Slash(bytes32 jobId,bytes32 contractHash,address worker,bytes32 receiptKey,uint8 fault,bytes32 evidence)"
                ),
                id,
                ch,
                worker,
                key,
                fault,
                evidence
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", _domain(address(esc)), structHash));
    }

    /// @dev Signatures from the first `count` members in ascending address order.
    function _sign(bytes32 digest, uint256 count) internal view returns (bytes memory out) {
        for (uint256 i = 0; i < count; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], digest);
            out = abi.encodePacked(out, r, s, v);
        }
    }

    function _settleSigs(bytes32 id, uint256 amountDue, address relay, uint256 count)
        internal
        view
        returns (bytes memory)
    {
        return _sign(_settleDigest(id, amountDue, relay, address(esc)), count);
    }

    /// @dev Settle with exactly the threshold of signatures. The committee signs the quoted price.
    function _settle(bytes32 id, address relay) internal {
        esc.settle(id, relay, _settleSigs(id, esc.priceOf(id), relay, T));
    }

    function _slash(bytes32 id, uint8 fault, bytes32 evidence) internal {
        esc.slash(id, SuriComAIEscrow.Fault(fault), evidence, _sign(_slashDigest(id, fault, evidence), T));
    }

    // -------------------------------------------------------------- asserts

    function eq(uint256 a, uint256 b, string memory what) internal pure {
        require(a == b, what);
    }

    function ok(bool c, string memory what) internal pure {
        require(c, what);
    }

    /// @dev The contract's token balance equals everything it says it holds or owes.
    function _solvent(address token) internal view {
        uint256 bal = MockUSDC(token).balanceOf(address(esc));
        eq(bal, esc.heldFees() + esc.heldBonds() + esc.totalClaimable() + esc.committeeCarry(), "solvency");
    }

    function _claim(address who) internal returns (uint256) {
        vm.prank(who);
        return esc.withdraw(who);
    }
}
