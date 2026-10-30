// SPDX-License-Identifier: LicenseRef-SuriComAI-Proprietary
pragma solidity 0.8.28;

import {SuriComAIEscrow} from "../src/SuriComAIEscrow.sol";
import {Fixture} from "./Fixture.sol";
import {MockUSDC, FeeToken, NoReturnToken, FalseToken, ReentrantToken, WeirdReturnToken} from "./Mocks.sol";

contract TokensTest is Fixture {
    function _escrowFor(address token) private returns (SuriComAIEscrow e) {
        e = new SuriComAIEscrow(_config(token));
        for (uint256 i = 0; i < 3; i++) {
            address who = i == 0 ? USER : (i == 1 ? WORKER : OTHER);
            (bool minted,) = token.call(abi.encodeWithSignature("mint(address,uint256)", who, 1e24));
            require(minted, "mint");
            vm.prank(who);
            (bool approved,) =
                token.call(abi.encodeWithSignature("approve(address,uint256)", address(e), type(uint256).max));
            require(approved, "approve");
        }
    }

    function test_a_fee_on_transfer_token_is_refused_on_lock_and_on_bond() public {
        FeeToken fee = new FeeToken();
        SuriComAIEscrow e = _escrowFor(address(fee));
        vm.prank(USER);
        vm.expectRevert(SuriComAIEscrow.WrongAmountReceived.selector);
        e.lock("f", CH, P, uint128(TOTAL), uint64(block.timestamp + 100), 0, WORKER);
    }

    function test_a_token_that_returns_false_is_refused() public {
        FalseToken bad = new FalseToken();
        SuriComAIEscrow e = new SuriComAIEscrow(_config(address(bad)));
        vm.prank(USER);
        vm.expectRevert(SuriComAIEscrow.TransferFailed.selector);
        e.lock("f", CH, P, uint128(TOTAL), uint64(block.timestamp + 100), 0, WORKER);
    }

    function test_a_token_that_returns_data_that_is_not_a_boolean_is_refused() public {
        WeirdReturnToken weird = new WeirdReturnToken();
        SuriComAIEscrow e = new SuriComAIEscrow(_config(address(weird)));
        uint256[4] memory lengths = [uint256(1), 31, 33, 64];
        for (uint256 i = 0; i < lengths.length; i++) {
            weird.setLen(lengths[i]);
            vm.prank(USER);
            vm.expectRevert(SuriComAIEscrow.TransferFailed.selector);
            e.lock(bytes32(i), CH, P, uint128(TOTAL), uint64(block.timestamp + 100), 0, WORKER);
        }
    }

    function test_a_token_that_returns_nothing_works_end_to_end() public {
        NoReturnToken old = new NoReturnToken();
        SuriComAIEscrow e = _escrowFor(address(old));
        vm.prank(USER);
        bytes32 id = e.lock("n", CH, P, uint128(TOTAL), uint64(block.timestamp + 3600), 200, WORKER);
        vm.prank(WORKER);
        e.postBond(id, PAYEE, KEY);
        (,,,,, address worker,, bytes32 ch, bytes32 key) = e.jobs(id);
        bytes32 structHash = keccak256(abi.encode(e.SETTLE_TYPEHASH(), id, ch, worker, key, uint256(P), address(0)));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", e.DOMAIN_SEPARATOR(), structHash));
        bytes memory sigs;
        for (uint256 i = 0; i < T; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], digest);
            sigs = abi.encodePacked(sigs, r, s, v);
        }
        e.settle(id, address(0), sigs);
        vm.prank(PAYEE);
        eq(e.withdraw(PAYEE), P, "paid through a token with no return value");
        eq(old.balanceOf(PAYEE), P, "received");
    }

    function test_a_token_that_calls_back_into_the_escrow_cannot_reenter() public {
        ReentrantToken evil = new ReentrantToken();
        SuriComAIEscrow e = _escrowFor(address(evil));
        evil.arm(address(e), abi.encodeCall(e.withdraw, (OTHER)));
        vm.prank(USER);
        e.lock("r", CH, P, uint128(TOTAL), uint64(block.timestamp + 100), 0, WORKER);
        ok(evil.attacked(), "the token did call back");
        ok(!evil.attackSucceeded(), "the callback failed");
        bytes memory result = evil.attackResult();
        ok(result.length == 4 && bytes4(result) == SuriComAIEscrow.Reentrancy.selector, "with the reentrancy error");
        eq(e.heldFees(), TOTAL, "state is intact");
    }

    function test_a_token_that_reenters_through_lock_or_bond_is_stopped_too() public {
        ReentrantToken evil = new ReentrantToken();
        SuriComAIEscrow e = _escrowFor(address(evil));
        evil.arm(
            address(e),
            abi.encodeCall(
                e.lock, (bytes32("again"), CH, P, uint128(TOTAL), uint64(block.timestamp + 100), uint128(0), WORKER)
            )
        );
        vm.prank(USER);
        e.lock("r2", CH, P, uint128(TOTAL), uint64(block.timestamp + 100), 0, WORKER);
        ok(!evil.attackSucceeded(), "nested lock refused");
        eq(e.heldFees(), TOTAL, "only one fee held");
    }

    function test_a_non_contract_token_cannot_be_used() public {
        SuriComAIEscrow.Config memory c = _config(address(0x1234));
        vm.expectRevert(SuriComAIEscrow.BadConfig.selector);
        new SuriComAIEscrow(c);
    }
}
