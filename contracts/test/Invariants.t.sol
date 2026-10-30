// SPDX-License-Identifier: LicenseRef-SuriComAI-Proprietary
pragma solidity 0.8.28;

import {SuriComAIEscrow} from "../src/SuriComAIEscrow.sol";
import {Fixture} from "./Fixture.sol";

/// @dev Performs random but well-formed actions against the escrow. Failed calls are expected
///      and ignored. Everything that succeeds is recorded in the ghost variables.
contract Handler is Fixture {
    bytes32[] public ids;
    uint256 public deposited;
    uint256 public withdrawn;
    uint256 private nonce;

    constructor(SuriComAIEscrow escrow, address token) {
        esc = escrow;
        usdc = MockUSDC(token);
        vm.warp(START);
        for (uint256 i = 0; i < N; i++) {
            keys.push(i + 1);
            members.push(vm.addr(i + 1));
        }
        for (uint256 i = 1; i < N; i++) {
            for (uint256 j = i; j > 0 && members[j] < members[j - 1]; j--) {
                (members[j], members[j - 1]) = (members[j - 1], members[j]);
                (keys[j], keys[j - 1]) = (keys[j - 1], keys[j]);
            }
        }
    }

    /// @dev Not a fuzz target: the inherited setup does nothing here.
    function setUp() public override {}

    function idCount() external view returns (uint256) {
        return ids.length;
    }

    function doLock(uint256 who, uint256 priceSeed, uint256 bondSeed, uint256 ttlSeed) external {
        address user = who % 2 == 0 ? USER : OTHER;
        uint128 price = uint128(10_000 + priceSeed % 500_000);
        uint128 bond = uint128(bondSeed % 2_000);
        uint64 ttl = uint64(60 + ttlSeed % 86_000);
        uint128 total = uint128(esc.quote(price).total);
        vm.prank(user);
        try esc.lock(bytes32(++nonce), CH, price, total, uint64(block.timestamp + ttl), bond, WORKER) returns (
            bytes32 id
        ) {
            ids.push(id);
            deposited += total;
        } catch {}
    }

    function doBond(uint256 idx) external {
        if (ids.length == 0) return;
        bytes32 id = ids[idx % ids.length];
        (,,,, uint128 bondRequired,,,,) = esc.jobs(id);
        vm.prank(WORKER);
        try esc.postBond(id, PAYEE, KEY) {
            deposited += bondRequired;
        } catch {}
    }

    function doSettle(uint256 idx, bool relay, uint256 sigSeed, bool wrongPrice) external {
        if (ids.length == 0) return;
        bytes32 id = ids[idx % ids.length];
        // The committee signs the quoted price. Sometimes sign another price, which must fail.
        uint256 price = esc.priceOf(id) + (wrongPrice ? 1 : 0);
        address relayPayee = relay ? RELAY : address(0);
        uint256 count = T + sigSeed % (N - T + 1);
        try esc.settle(id, relayPayee, _settleSigs(id, price, relayPayee, count)) {} catch {}
    }

    function doSlash(uint256 idx, uint256 faultSeed, bytes32 evidence) external {
        if (ids.length == 0) return;
        bytes32 id = ids[idx % ids.length];
        uint8 fault = uint8(1 + faultSeed % 4);
        bytes32 ev = evidence == bytes32(0) ? bytes32(uint256(1)) : evidence;
        try esc.slash(id, SuriComAIEscrow.Fault(fault), ev, _sign(_slashDigest(id, fault, ev), T)) {} catch {}
    }

    function doExpire(uint256 idx) external {
        if (ids.length == 0) return;
        try esc.expire(ids[idx % ids.length]) {} catch {}
    }

    function doWarp(uint256 dt) external {
        vm.warp(block.timestamp + dt % 2 days);
    }

    function doPause(bool on) external {
        vm.prank(GUARDIAN);
        if (on) esc.pause();
        else esc.unpause();
    }

    function doWithdraw(uint256 who) external {
        address[10] memory actors =
            [USER, WORKER, PAYEE, RELAY, PROTOCOL, OTHER, esc.BURN(), members[0], members[1], members[4]];
        address a = actors[who % actors.length];
        vm.prank(a);
        try esc.withdraw(a) returns (uint256 amount) {
            withdrawn += amount;
        } catch {}
    }
}

import {MockUSDC} from "./Mocks.sol";

contract InvariantsTest is Fixture {
    Handler private handler;
    mapping(bytes32 => SuriComAIEscrow.Phase) private seenTerminal;

    function setUp() public override {
        super.setUp();
        handler = new Handler(esc, address(usdc));
        // The handler acts as USER, WORKER and OTHER through prank, so they must have funds and approvals.
    }

    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(handler);
    }

    /// @dev Money held plus money owed equals the token balance, and nothing appears from nowhere.
    function invariant_solvency_and_conservation() public view {
        uint256 bal = usdc.balanceOf(address(esc));
        eq(
            bal,
            esc.heldFees() + esc.heldBonds() + esc.totalClaimable() + esc.committeeCarry(),
            "balance equals held plus owed plus the committee carry"
        );
        eq(bal, handler.deposited() - handler.withdrawn(), "balance equals deposits minus withdrawals");
    }

    /// @dev Reservations match the jobs that are still open, per user and in total.
    function invariant_reservations_match_open_jobs() public view {
        uint256 total;
        uint256 fees;
        uint256 userA;
        uint256 userB;
        uint256 bonds;
        for (uint256 i = 0; i < handler.idCount(); i++) {
            (address user,, SuriComAIEscrow.Phase phase, uint128 cap, uint128 bondReq,,,,) = esc.jobs(handler.ids(i));
            if (phase == SuriComAIEscrow.Phase.Locked || phase == SuriComAIEscrow.Phase.Bonded) {
                total += uint256(cap) + bondReq;
                fees += cap;
                if (phase == SuriComAIEscrow.Phase.Bonded) bonds += bondReq;
                if (user == USER) userA += cap;
                else userB += cap;
            }
        }
        eq(esc.lockedGlobal(), total, "global reservation");
        eq(esc.heldFees(), fees, "held fees");
        eq(esc.heldBonds(), bonds, "held bonds");
        eq(esc.lockedByUser(USER), userA, "user A reservation");
        eq(esc.lockedByUser(OTHER), userB, "user B reservation");
    }

    /// @dev A job that reached a terminal phase never leaves it or changes to another one.
    function invariant_terminal_phases_are_final() public {
        for (uint256 i = 0; i < handler.idCount(); i++) {
            bytes32 id = handler.ids(i);
            SuriComAIEscrow.Phase phase = _phase(id);
            if (phase >= SuriComAIEscrow.Phase.Paid) {
                SuriComAIEscrow.Phase before = seenTerminal[id];
                if (before == SuriComAIEscrow.Phase.None) seenTerminal[id] = phase;
                else ok(before == phase, "terminal phase changed");
            }
        }
    }

    /// @dev Every credit goes to a known account, so the balances of those accounts add up
    ///      to exactly the amount the contract says it owes.
    function invariant_every_owed_amount_belongs_to_a_known_account() public view {
        address[12] memory known = [
            USER,
            WORKER,
            PAYEE,
            RELAY,
            PROTOCOL,
            OTHER,
            esc.BURN(),
            members[0],
            members[1],
            members[2],
            members[3],
            members[4]
        ];
        uint256 sum;
        for (uint256 i = 0; i < known.length; i++) {
            sum += esc.claimableOf(known[i]);
        }
        eq(sum, esc.totalClaimable(), "owed to known accounts equals the total owed");
    }
}
