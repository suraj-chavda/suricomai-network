// SPDX-License-Identifier: LicenseRef-SuriComAI-Proprietary
pragma solidity 0.8.28;

import {SuriComAIEscrow} from "../src/SuriComAIEscrow.sol";
import {Fixture} from "./Fixture.sol";

/// @dev Default schedule: 1 percent protocol, 1 percent attestation with a floor of 2000 units,
///      up to 1 percent relay. For a price of 1_000_000 every line is exactly 10_000 and the total
///      is 1_030_000. Each committee member's share of the attestation line is 2_000.
contract LifecycleTest is Fixture {
    uint256 private constant MEMBER_SHARE = ATT / N;

    // ------------------------------------------------------------------ quote

    function test_quote_prices_a_one_dollar_job_by_hand() public view {
        SuriComAIEscrow.Quote memory q = esc.quote(P);
        eq(q.price, P, "price");
        eq(q.protocol, PROTO, "protocol");
        eq(q.attestation, ATT, "attestation");
        eq(q.relayMax, RLY, "relay");
        eq(q.total, TOTAL, "total");
    }

    function test_quote_floor_rounding_and_the_smallest_job() public view {
        // 0.01 USD: 1 percent is 100, so the attestation line is the 2000 floor.
        SuriComAIEscrow.Quote memory small = esc.quote(esc.MIN_PRICE());
        eq(small.protocol, 100, "protocol");
        eq(small.attestation, 2_000, "floor");
        eq(small.relayMax, 100, "relay");
        eq(small.total, 12_200, "total");
        // 10_001 * 100 bps is 100.01 units, which rounds up to 101 and not down to 100.
        SuriComAIEscrow.Quote memory up = esc.quote(10_001);
        eq(up.protocol, 101, "rounds up");
        eq(up.relayMax, 101, "rounds up");
    }

    function test_quote_refuses_a_price_below_the_minimum_and_a_total_past_64_bits() public {
        vm.expectRevert(SuriComAIEscrow.PriceTooSmall.selector);
        esc.quote(uint128(esc.MIN_PRICE() - 1));
        vm.expectRevert(SuriComAIEscrow.PriceTooSmall.selector);
        esc.quote(0);
        vm.expectRevert(SuriComAIEscrow.FeeOverflow.selector);
        esc.quote(type(uint64).max);
        vm.expectRevert(SuriComAIEscrow.FeeOverflow.selector);
        esc.quote(type(uint128).max);
        // Half of the 64 bit range plus its lines still fits and is priced exactly.
        SuriComAIEscrow.Quote memory big = esc.quote(type(uint64).max / 2);
        eq(big.total, big.price + big.protocol + big.attestation + big.relayMax, "sums");
    }

    function test_every_quote_sums_and_stays_within_its_rate() public view {
        for (uint256 price = esc.MIN_PRICE(); price < esc.MIN_PRICE() + 3_000; price++) {
            SuriComAIEscrow.Quote memory q = esc.quote(uint128(price));
            eq(q.total, q.price + q.protocol + q.attestation + q.relayMax, "sum");
            ok(q.protocol * 10_000 >= price * 100 && q.protocol * 10_000 < price * 100 + 10_000, "protocol rounds up by less than a unit");
            ok(q.relayMax * 10_000 >= price * 100 && q.relayMax * 10_000 < price * 100 + 10_000, "relay rounds up by less than a unit");
            ok(q.attestation >= 2_000 && q.attestation * 10_000 >= price * 100, "attestation floor and rate");
        }
    }

    // ------------------------------------------------------------------ lock

    function test_lock_pulls_the_whole_quote_and_records_the_job() public {
        uint256 before = usdc.balanceOf(USER);
        bytes32 id = _lock("a", P, 400, 3600);
        eq(before - usdc.balanceOf(USER), TOTAL, "the user paid the quoted total and nothing else");
        eq(esc.heldFees(), TOTAL, "held fees");
        eq(esc.lockedGlobal(), TOTAL + 400, "reserved includes the bond");
        eq(esc.lockedByUser(USER), TOTAL, "user locked");
        eq(esc.priceOf(id), P, "price recorded");
        (
            address user,
            uint64 expiry,
            SuriComAIEscrow.Phase phase,
            uint128 cap,
            uint128 bondReq,
            address worker,,
            bytes32 ch,
        ) = _job(id);
        ok(user == USER && worker == WORKER, "parties");
        eq(expiry, block.timestamp + 3600, "expiry");
        ok(phase == SuriComAIEscrow.Phase.Locked, "phase");
        eq(cap, TOTAL, "the locked amount is the quote total");
        eq(bondReq, 400, "bond required");
        ok(ch == CH, "contract hash");
        _solvent(address(usdc));
    }

    function test_lock_job_id_commits_to_the_caller() public {
        bytes32 mine = keccak256(abi.encode(USER, bytes32("s")));
        bytes32 theirs = keccak256(abi.encode(OTHER, bytes32("s")));
        ok(mine != theirs, "ids differ");
        vm.prank(OTHER);
        bytes32 got = esc.lock("s", CH, P, uint128(TOTAL), uint64(block.timestamp + 100), 0, WORKER);
        ok(got == theirs && got != mine, "a stranger gets a different id, never the victim's");
        bytes32 victim = _lock("s", P, 0, 100);
        ok(victim == mine, "the victim's own lock still works");
    }

    function test_lock_rejects_bad_inputs() public {
        vm.startPrank(USER);
        uint64 ok1 = uint64(block.timestamp + 100);
        uint128 max = uint128(TOTAL);
        vm.expectRevert(SuriComAIEscrow.ZeroValue.selector);
        esc.lock("1", bytes32(0), P, max, ok1, 0, WORKER);
        vm.expectRevert(SuriComAIEscrow.ZeroValue.selector);
        esc.lock("1", CH, P, max, ok1, 0, address(0));
        vm.expectRevert(SuriComAIEscrow.PriceTooSmall.selector);
        esc.lock("1", CH, 9_999, max, ok1, 0, WORKER);
        vm.expectRevert(SuriComAIEscrow.BadExpiry.selector);
        esc.lock("1", CH, P, max, uint64(block.timestamp), 0, WORKER);
        vm.expectRevert(SuriComAIEscrow.BadExpiry.selector);
        esc.lock("1", CH, P, max, uint64(block.timestamp - 1), 0, WORKER);
        vm.expectRevert(SuriComAIEscrow.TtlTooLong.selector);
        esc.lock("1", CH, P, max, uint64(block.timestamp + 1 days + 1), 0, WORKER);
        esc.lock("1", CH, P, max, uint64(block.timestamp + 1 days), 0, WORKER);
        vm.expectRevert(SuriComAIEscrow.JobExists.selector);
        esc.lock("1", CH, P, max, ok1, 0, WORKER);
        vm.stopPrank();
    }

    function test_lock_refuses_a_total_above_what_the_user_agreed_to() public {
        uint64 exp = uint64(block.timestamp + 100);
        vm.startPrank(USER);
        vm.expectRevert(SuriComAIEscrow.OverMax.selector);
        esc.lock("m1", CH, P, uint128(TOTAL - 1), exp, 0, WORKER);
        vm.expectRevert(SuriComAIEscrow.OverMax.selector);
        esc.lock("m2", CH, P, 0, exp, 0, WORKER);
        uint256 before = usdc.balanceOf(USER);
        esc.lock("m3", CH, P, uint128(TOTAL), exp, 0, WORKER);
        eq(before - usdc.balanceOf(USER), TOTAL, "exactly the agreed total, not more");
        vm.stopPrank();
        eq(esc.heldFees(), TOTAL, "the refused attempts held nothing");
    }

    // ------------------------------------------------------------------ bond

    function test_bond_records_the_worker_and_holds_the_bond() public {
        bytes32 id = _lock("b", P, 400, 3600);
        uint256 before = usdc.balanceOf(WORKER);
        _bond(id);
        eq(before - usdc.balanceOf(WORKER), 400, "bond pulled");
        eq(esc.heldBonds(), 400, "held bonds");
        (,, SuriComAIEscrow.Phase phase,,,, address payee,, bytes32 key) = _job(id);
        ok(phase == SuriComAIEscrow.Phase.Bonded && payee == PAYEE && key == KEY, "recorded");
        _solvent(address(usdc));
    }

    function test_bond_only_by_the_pinned_worker_once_and_before_expiry() public {
        bytes32 id = _lock("c", P, 400, 3600);
        vm.prank(OTHER);
        vm.expectRevert(SuriComAIEscrow.NotWorker.selector);
        esc.postBond(id, PAYEE, KEY);
        vm.prank(USER);
        vm.expectRevert(SuriComAIEscrow.NotWorker.selector);
        esc.postBond(id, PAYEE, KEY);
        vm.startPrank(WORKER);
        vm.expectRevert(SuriComAIEscrow.ZeroValue.selector);
        esc.postBond(id, address(0), KEY);
        vm.expectRevert(SuriComAIEscrow.ZeroValue.selector);
        esc.postBond(id, PAYEE, bytes32(0));
        esc.postBond(id, PAYEE, KEY);
        vm.expectRevert(SuriComAIEscrow.BadPhase.selector);
        esc.postBond(id, PAYEE, KEY);
        vm.stopPrank();

        bytes32 late = _lock("late", P, 400, 100);
        vm.warp(block.timestamp + 100);
        vm.prank(WORKER);
        vm.expectRevert(SuriComAIEscrow.AlreadyExpired.selector);
        esc.postBond(late, PAYEE, KEY);
    }

    function test_bond_of_zero_moves_no_tokens() public {
        bytes32 id = _lock("z", P, 0, 3600);
        uint256 before = usdc.balanceOf(WORKER);
        _bond(id);
        eq(usdc.balanceOf(WORKER), before, "nothing pulled");
        ok(_phase(id) == SuriComAIEscrow.Phase.Bonded, "bonded");
    }

    function test_bond_on_an_unknown_job_is_refused() public {
        vm.prank(WORKER);
        vm.expectRevert(SuriComAIEscrow.BadPhase.selector);
        esc.postBond(bytes32(uint256(7)), PAYEE, KEY);
    }

    // ---------------------------------------------------------------- settle

    function test_settle_pays_every_line_to_its_owner_and_the_parts_sum_to_the_total() public {
        bytes32 id = _bonded("s1", P, 500);
        _settle(id, RELAY);
        eq(esc.claimableOf(PAYEE), P, "the worker gets exactly the price, nothing deducted");
        eq(esc.claimableOf(RELAY), RLY, "relay line");
        eq(esc.claimableOf(PROTOCOL), PROTO, "protocol line");
        eq(esc.claimableOf(WORKER), 500, "bond back");
        eq(esc.claimableOf(USER), 0, "no refund when a relay carried the job");
        for (uint256 i = 0; i < N; i++) {
            eq(esc.claimableOf(members[i]), MEMBER_SHARE, "committee share");
        }
        eq(esc.committeeCarry(), 0, "the attestation line divided evenly");
        eq(esc.totalClaimable(), TOTAL + 500, "every unit locked is now owed to someone");
        ok(_phase(id) == SuriComAIEscrow.Phase.Paid, "paid");
        eq(esc.heldFees(), 0, "fees released");
        eq(esc.heldBonds(), 0, "bonds released");
        eq(esc.lockedGlobal(), 0, "reservation released");
        eq(esc.lockedByUser(USER), 0, "user reservation released");
        _solvent(address(usdc));
    }

    function test_settle_with_no_relay_refunds_the_relay_line_to_the_user() public {
        bytes32 id = _bonded("s2", P, 0);
        _settle(id, address(0));
        eq(esc.claimableOf(USER), RLY, "an unused relay line comes back to the user");
        eq(esc.claimableOf(PROTOCOL), PROTO, "the protocol takes only its own line");
        eq(esc.claimableOf(RELAY), 0, "no relay");
        _solvent(address(usdc));
    }

    function test_the_attestation_remainder_carries_forward_and_no_unit_is_kept_by_anyone_else() public {
        // A floor of 2003 does not divide by 5 members, so a remainder is left each time.
        SuriComAIEscrow.Config memory c = _config(address(usdc));
        c.attestationMin = 2_003;
        c.attestationBps = 0;
        esc = new SuriComAIEscrow(c);
        _fund(address(usdc), address(esc));
        uint256 lines;
        for (uint256 i = 0; i < 20; i++) {
            bytes32 id = _bonded(bytes32(i + 1), P, 0);
            _settle(id, RELAY);
            lines += 2_003;
            uint256 paidToMembers;
            for (uint256 m = 0; m < N; m++) {
                paidToMembers += esc.claimableOf(members[m]);
            }
            eq(paidToMembers + esc.committeeCarry(), lines, "members plus carry equal every attestation line");
            ok(esc.committeeCarry() < N, "the carry never reaches one unit per member");
            eq(esc.claimableOf(PROTOCOL), (i + 1) * 10_000, "the protocol never takes a remainder");
            _solvent(address(usdc));
        }
    }

    function test_settle_rounding_never_creates_or_loses_value() public {
        for (uint256 price = 10_000; price <= 10_040; price++) {
            bytes32 id = _bonded(bytes32(price), uint128(price), 7);
            uint256 total = esc.quote(uint128(price)).total;
            uint256 owedBefore = esc.totalClaimable();
            uint256 carryBefore = esc.committeeCarry();
            _settle(id, price % 2 == 0 ? RELAY : address(0));
            eq(
                (esc.totalClaimable() - owedBefore) + (esc.committeeCarry() - carryBefore),
                total + 7,
                "everything put in comes out"
            );
            _solvent(address(usdc));
        }
    }

    function test_settle_is_phase_and_time_checked() public {
        bytes32 id = _lock("s5", P, 0, 3600);
        vm.expectRevert(SuriComAIEscrow.BadPhase.selector);
        esc.settle(id, address(0), hex"");
        _bond(id);
        vm.warp(block.timestamp + 3600);
        bytes memory sigs = _settleSigs(id, P, address(0), T);
        vm.expectRevert(SuriComAIEscrow.AlreadyExpired.selector);
        esc.settle(id, address(0), sigs);
    }

    function test_second_settle_and_cross_transitions_are_refused() public {
        bytes32 id = _bonded("s6", P, 100);
        bytes memory settleSigs = _settleSigs(id, P, address(0), T);
        bytes memory slashSigs = _sign(_slashDigest(id, 3, bytes32(uint256(1))), T);
        _settle(id, address(0));
        vm.expectRevert(SuriComAIEscrow.BadPhase.selector);
        esc.settle(id, address(0), settleSigs);
        vm.expectRevert(SuriComAIEscrow.BadPhase.selector);
        esc.slash(id, SuriComAIEscrow.Fault.BadQuote, bytes32(uint256(1)), slashSigs);
        vm.warp(block.timestamp + 7200);
        vm.expectRevert(SuriComAIEscrow.BadPhase.selector);
        esc.expire(id);
        _solvent(address(usdc));
    }

    // ---------------------------------------------------------------- expire

    function test_expire_returns_the_whole_total_and_the_bond_to_the_user_with_nobody_else() public {
        bytes32 id = _bonded("e1", P, 300);
        vm.expectRevert(SuriComAIEscrow.NotExpired.selector);
        esc.expire(id);
        vm.warp(block.timestamp + 3600);
        vm.prank(OTHER);
        esc.expire(id);
        eq(esc.claimableOf(USER), TOTAL + 300, "every fee line and the missed-deadline bond");
        eq(esc.claimableOf(WORKER), 0, "worker gets nothing");
        ok(_phase(id) == SuriComAIEscrow.Phase.Expired, "expired");
        _solvent(address(usdc));
    }

    function test_a_job_that_is_not_delivered_takes_no_fee_of_any_kind() public {
        bytes32 expired = _bonded("nf1", P, 100);
        bytes32 slashed = _bonded("nf2", P, 100);
        vm.warp(block.timestamp + 3600);
        esc.expire(expired);
        _slash(slashed, 4, keccak256("evidence"));
        eq(esc.claimableOf(PROTOCOL), 0, "no protocol fee on a failed job");
        eq(esc.claimableOf(RELAY), 0, "no relay fee");
        eq(esc.committeeCarry(), 0, "no attestation fee carried");
        for (uint256 i = 0; i < N; i++) {
            eq(esc.claimableOf(members[i]), 0, "the committee earns nothing on a failed job");
        }
        eq(esc.claimableOf(USER), 2 * TOTAL + 100 + 50, "the user gets every unit of both totals, the missed bond and half the seized one");
        _solvent(address(usdc));
    }

    function test_expire_without_a_bond_returns_only_the_total() public {
        bytes32 id = _lock("e2", P, 300, 3600);
        vm.warp(block.timestamp + 3600);
        esc.expire(id);
        eq(esc.claimableOf(USER), TOTAL, "total only");
        eq(esc.lockedGlobal(), 0, "the unused bond reservation is released");
        _solvent(address(usdc));
    }

    function test_expire_works_while_paused_and_only_once() public {
        bytes32 id = _lock("e3", P, 0, 3600);
        vm.prank(GUARDIAN);
        esc.pause();
        vm.warp(block.timestamp + 3600);
        esc.expire(id);
        vm.expectRevert(SuriComAIEscrow.BadPhase.selector);
        esc.expire(id);
    }

    function test_expire_then_settle_is_refused() public {
        bytes32 id = _bonded("e4", P, 0);
        bytes memory sigs = _settleSigs(id, P, address(0), T);
        vm.warp(block.timestamp + 3600);
        esc.expire(id);
        vm.expectRevert(SuriComAIEscrow.BadPhase.selector);
        esc.settle(id, address(0), sigs);
    }

    function test_expire_of_an_unknown_job_is_refused() public {
        vm.expectRevert(SuriComAIEscrow.BadPhase.selector);
        esc.expire(bytes32(uint256(99)));
    }

    // ----------------------------------------------------------------- slash

    function test_slash_refunds_the_user_and_nobody_profits_from_the_seized_bond() public {
        bytes32 id = _bonded("sl1", P, 400);
        _slash(id, 3, keccak256("evidence"));
        eq(esc.claimableOf(USER), TOTAL + 200, "the whole total plus half the bond");
        eq(esc.claimableOf(esc.BURN()), 200, "the other half of the bond goes where nobody can withdraw it");
        eq(esc.claimableOf(PROTOCOL), 0, "the protocol fee recipient earns nothing from a slash");
        eq(esc.claimableOf(WORKER), 0, "worker loses the bond");
        for (uint256 i = 0; i < N; i++) {
            eq(esc.claimableOf(members[i]), 0, "the committee earns nothing from a slash");
        }
        ok(_phase(id) == SuriComAIEscrow.Phase.Slashed, "slashed");
        _solvent(address(usdc));
    }

    function test_slash_before_a_bond_refunds_the_total_and_seizes_nothing() public {
        bytes32 id = _lock("sl2", P, 400, 3600);
        _slash(id, 2, keccak256("no gpu"));
        eq(esc.claimableOf(USER), TOTAL, "total back");
        eq(esc.claimableOf(esc.BURN()), 0, "no bond to seize");
        eq(esc.lockedGlobal(), 0, "reservation released");
        _solvent(address(usdc));
    }

    function test_slash_needs_evidence_and_a_real_fault() public {
        bytes32 id = _bonded("sl3", P, 100);
        vm.expectRevert(SuriComAIEscrow.NoEvidence.selector);
        esc.slash(id, SuriComAIEscrow.Fault.BadQuote, bytes32(0), hex"");
        vm.expectRevert(SuriComAIEscrow.BadFault.selector);
        esc.slash(id, SuriComAIEscrow.Fault.None, bytes32(uint256(1)), hex"");
        // An out of range enum value is refused by the ABI decoder.
        (bool okCall,) =
            address(esc).call(abi.encodeWithSelector(esc.slash.selector, id, uint8(9), bytes32(uint256(1)), hex""));
        ok(!okCall, "fault 9 refused");
    }

    function test_slash_is_still_possible_after_expiry_until_someone_expires_it() public {
        bytes32 id = _bonded("sl4", P, 100);
        vm.warp(block.timestamp + 7200);
        _slash(id, 4, keccak256("late evidence"));
        ok(_phase(id) == SuriComAIEscrow.Phase.Slashed, "slashed after expiry");
    }

    function test_slash_then_settle_or_expire_is_refused() public {
        bytes32 id = _bonded("sl5", P, 100);
        _slash(id, 1, keccak256("e"));
        vm.expectRevert(SuriComAIEscrow.BadPhase.selector);
        esc.settle(id, address(0), hex"");
        vm.warp(block.timestamp + 7200);
        vm.expectRevert(SuriComAIEscrow.BadPhase.selector);
        esc.expire(id);
    }

    // -------------------------------------------------------------- withdraw

    function test_withdraw_pays_once_and_zeroes_the_balance() public {
        bytes32 id = _bonded("w1", P, 100);
        _settle(id, address(0));
        uint256 before = usdc.balanceOf(PAYEE);
        eq(_claim(PAYEE), P, "paid");
        eq(usdc.balanceOf(PAYEE) - before, P, "received");
        vm.prank(PAYEE);
        vm.expectRevert(SuriComAIEscrow.NothingToWithdraw.selector);
        esc.withdraw(PAYEE);
        _solvent(address(usdc));
    }

    function test_withdraw_can_redirect_and_refuses_the_zero_address() public {
        bytes32 id = _bonded("w2", P, 0);
        _settle(id, address(0));
        vm.prank(PAYEE);
        vm.expectRevert(SuriComAIEscrow.ZeroValue.selector);
        esc.withdraw(address(0));
        vm.prank(PAYEE);
        esc.withdraw(OTHER);
        eq(esc.claimableOf(PAYEE), 0, "drained");
    }

    function test_a_frozen_recipient_blocks_only_themselves() public {
        bytes32 id = _bonded("w3", P, 100);
        _settle(id, RELAY);
        usdc.block_(RELAY, true);
        vm.prank(RELAY);
        vm.expectRevert(SuriComAIEscrow.TransferFailed.selector);
        esc.withdraw(RELAY);
        eq(esc.claimableOf(RELAY), RLY, "the frozen balance is intact");
        eq(_claim(PAYEE), P, "everyone else is unaffected");
        eq(_claim(PROTOCOL), PROTO, "the protocol recipient is unaffected");
        vm.prank(RELAY);
        esc.withdraw(OTHER);
        eq(esc.claimableOf(RELAY), 0, "a frozen account can still redirect to a clean address");
    }

    function test_a_frozen_protocol_recipient_blocks_nobody_else() public {
        bytes32 id = _bonded("w4", P, 0);
        _settle(id, RELAY);
        usdc.block_(PROTOCOL, true);
        vm.prank(PROTOCOL);
        vm.expectRevert(SuriComAIEscrow.TransferFailed.selector);
        esc.withdraw(PROTOCOL);
        eq(_claim(PAYEE), P, "the worker is paid");
        eq(_claim(RELAY), RLY, "the relay is paid");
        eq(_claim(members[0]), MEMBER_SHARE, "the committee is paid");
        // A later settlement still works while the recipient is frozen.
        bytes32 next = _bonded("w5", P, 0);
        _settle(next, address(0));
        eq(esc.claimableOf(PROTOCOL), 2 * PROTO, "the frozen balance keeps accruing and is intact");
    }

    function test_committee_members_collect_a_share_of_every_settlement() public {
        for (uint256 i = 0; i < 3; i++) {
            bytes32 id = _bonded(bytes32(i + 1), P, 0);
            _settle(id, address(0));
        }
        eq(esc.claimableOf(members[0]), 3 * MEMBER_SHARE, "three settlements");
        eq(_claim(members[0]), 3 * MEMBER_SHARE, "claimed");
        eq(esc.claimableOf(members[0]), 0, "drained");
        bytes32 more = _bonded("later", P, 0);
        _settle(more, address(0));
        eq(esc.claimableOf(members[0]), MEMBER_SHARE, "only the new share");
        eq(esc.claimableOf(members[4]), 4 * MEMBER_SHARE, "an idle member kept accruing");
        _solvent(address(usdc));
    }

    function test_a_committee_member_who_is_also_a_payee_claims_both() public {
        bytes32 id = _lock("both", P, 0, 3600);
        vm.prank(WORKER);
        esc.postBond(id, members[1], KEY);
        _settle(id, address(0));
        eq(esc.claimableOf(members[1]), P + MEMBER_SHARE, "worker price plus committee share");
        eq(_claim(members[1]), P + MEMBER_SHARE, "single withdrawal pays both");
        _solvent(address(usdc));
    }

    // ----------------------------------------------------------------- pause

    function test_pause_blocks_only_new_locks() public {
        bytes32 id = _bonded("p1", P, 0);
        bytes32 open = _lock("p2", P, 0, 3600);
        vm.prank(OTHER);
        vm.expectRevert(SuriComAIEscrow.NotGuardian.selector);
        esc.pause();
        vm.prank(GUARDIAN);
        esc.pause();
        vm.prank(USER);
        vm.expectRevert(SuriComAIEscrow.Paused.selector);
        esc.lock("p3", CH, P, uint128(TOTAL), uint64(block.timestamp + 100), 0, WORKER);
        _bond(open);
        _settle(id, address(0));
        eq(_claim(PAYEE), P, "withdrawals work while paused");
        vm.prank(OTHER);
        vm.expectRevert(SuriComAIEscrow.NotGuardian.selector);
        esc.unpause();
        vm.prank(GUARDIAN);
        esc.unpause();
        _lock("p4", P, 0, 100);
    }

    // ------------------------------------------------------------------ caps

    function test_global_and_user_caps_hold_at_the_boundary_and_release() public {
        // A price of 100_000 quotes to 104_000. With a bond of 50_000 a job reserves 154_000.
        SuriComAIEscrow.Config memory c = _config(address(usdc));
        c.startCap = 308_000;
        c.maxCap = 308_000;
        c.userCap = 150_000;
        esc = new SuriComAIEscrow(c);
        _fund(address(usdc), address(esc));
        uint256 exp = block.timestamp + 100;
        vm.prank(USER);
        bytes32 a = esc.lock("a", CH, 100_000, 104_000, uint64(exp), 50_000, WORKER);
        eq(esc.lockedGlobal(), 154_000, "reservation counts the bond");
        vm.prank(USER);
        vm.expectRevert(SuriComAIEscrow.UserCapExceeded.selector);
        esc.lock("b", CH, 50_000, 53_000, uint64(exp), 0, WORKER);
        vm.prank(OTHER);
        vm.expectRevert(SuriComAIEscrow.GlobalCap.selector);
        esc.lock("c", CH, 100_000, 104_000, uint64(exp), 50_001, WORKER);
        vm.prank(OTHER);
        esc.lock("d", CH, 100_000, 104_000, uint64(exp), 50_000, WORKER);
        eq(esc.lockedGlobal(), 308_000, "exactly at the cap is allowed");
        vm.warp(block.timestamp + 100);
        esc.expire(a);
        eq(esc.lockedGlobal(), 154_000, "released after the job ends");
        vm.prank(USER);
        esc.lock("e", CH, 100_000, 104_000, uint64(block.timestamp + 100), 50_000, WORKER);
    }

    function test_the_global_cap_rises_on_a_fixed_schedule_and_stops_at_the_maximum() public {
        SuriComAIEscrow.Config memory c = _config(address(usdc));
        c.startCap = 1_000;
        c.capStep = 500;
        c.capPeriod = 1 days;
        c.maxCap = 2_200;
        esc = new SuriComAIEscrow(c);
        uint256 t0 = block.timestamp;
        eq(esc.capAt(t0), 1_000, "start");
        eq(esc.capAt(t0 - 5), 1_000, "before launch");
        eq(esc.capAt(t0 + 1 days - 1), 1_000, "just before the first step");
        eq(esc.capAt(t0 + 1 days), 1_500, "first step");
        eq(esc.capAt(t0 + 2 days), 2_000, "second step");
        eq(esc.capAt(t0 + 3 days), 2_200, "clamped to the maximum");
        eq(esc.capAt(t0 + 100_000 days), 2_200, "stays clamped");
    }

    // -------------------------------------------------------- very large sums

    function test_amounts_near_the_top_of_the_range_settle_exactly() public {
        SuriComAIEscrow.Config memory c = _config(address(usdc));
        uint256 huge = uint256(type(uint128).max) - 1;
        c.startCap = type(uint256).max / 4;
        c.maxCap = type(uint256).max / 4;
        c.userCap = type(uint256).max / 4;
        esc = new SuriComAIEscrow(c);
        uint128 bigPrice = type(uint64).max / 2;
        uint256 total = esc.quote(bigPrice).total;
        usdc.mint(USER, total);
        usdc.mint(WORKER, huge);
        _fund(address(usdc), address(esc));
        vm.prank(USER);
        bytes32 id = esc.lock("huge", CH, bigPrice, uint128(total), uint64(block.timestamp + 100), uint128(huge), WORKER);
        _bond(id);
        uint256 owedBefore = esc.totalClaimable();
        uint256 carryBefore = esc.committeeCarry();
        esc.settle(id, address(0), _settleSigs(id, bigPrice, address(0), T));
        eq(
            (esc.totalClaimable() - owedBefore) + (esc.committeeCarry() - carryBefore),
            total + huge,
            "nothing lost at the extremes"
        );
        _solvent(address(usdc));
    }

    // ------------------------------------------------------------------ fuzz

    function testFuzz_every_settlement_conserves_value(uint128 price, uint128 bond, bool relay) public {
        price = uint128(10_000 + (uint256(price) % 1e12));
        bond = uint128(uint256(bond) % 1e12);
        bytes32 id = _bonded(keccak256(abi.encode(price, bond, relay)), price, bond);
        uint256 total = esc.quote(price).total;
        uint256 owedBefore = esc.totalClaimable();
        uint256 carryBefore = esc.committeeCarry();
        _settle(id, relay ? RELAY : address(0));
        eq(
            (esc.totalClaimable() - owedBefore) + (esc.committeeCarry() - carryBefore),
            total + bond,
            "value in equals value out"
        );
        eq(esc.claimableOf(PAYEE), price, "the worker always gets exactly the price");
        eq(esc.heldFees() + esc.heldBonds(), 0, "nothing left held");
        _solvent(address(usdc));
    }

    function testFuzz_every_expiry_and_slash_conserves_value_and_takes_no_fee(
        uint128 price,
        uint128 bond,
        bool bonded,
        bool slashIt
    ) public {
        price = uint128(10_000 + (uint256(price) % 1e12));
        bond = uint128(uint256(bond) % 1e12);
        bytes32 id = _lock(keccak256(abi.encode(price, bond, bonded, slashIt)), price, bond, 3600);
        if (bonded) _bond(id);
        uint256 before = esc.totalClaimable();
        uint256 total = esc.quote(price).total;
        uint256 expectedOut = total + (bonded ? bond : 0);
        if (slashIt) {
            _slash(id, 4, keccak256("fuzz evidence"));
        } else {
            vm.warp(block.timestamp + 3600);
            esc.expire(id);
        }
        eq(esc.totalClaimable() - before, expectedOut, "value in equals value out");
        eq(esc.claimableOf(PROTOCOL), 0, "no protocol fee");
        eq(esc.committeeCarry(), 0, "no attestation fee");
        eq(esc.lockedGlobal(), 0, "reservation released");
        _solvent(address(usdc));
    }
}
