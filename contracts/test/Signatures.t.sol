// SPDX-License-Identifier: LicenseRef-SuriComAI-Proprietary
pragma solidity 0.8.28;

import {SuriComAIEscrow} from "../src/SuriComAIEscrow.sol";
import {Fixture} from "./Fixture.sol";

contract SignaturesTest is Fixture {
    uint256 private constant CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    bytes32 private id;

    function setUp() public override {
        super.setUp();
        id = _bonded("sig", P, 100);
    }

    function _bad(bytes memory sigs) private {
        vm.expectRevert(SuriComAIEscrow.BadSignatures.selector);
        esc.settle(id, address(0), sigs);
    }

    /// @dev Reference values computed with `cast` (a separate implementation), for a chain id of
    ///      31337. The Rust attestor service must reproduce them byte for byte.
    function test_the_typed_data_digests_match_the_reference_vectors() public view {
        bytes32 j = bytes32(hex"1111111111111111111111111111111111111111111111111111111111111111");
        bytes32 c = bytes32(hex"2222222222222222222222222222222222222222222222222222222222222222");
        bytes32 k = bytes32(hex"4444444444444444444444444444444444444444444444444444444444444444");
        bytes32 got = _settleDigestFor(j, c, address(3), k, 1000, address(5), address(6));
        ok(got == 0x305b610578f7ad08d19ed189485e8656c3a42733a4a8de871f057e88e33e9105, "settle digest");

        bytes32 ev = bytes32(hex"5555555555555555555555555555555555555555555555555555555555555555");
        bytes32 slashStruct = keccak256(
            abi.encode(
                keccak256(
                    "Slash(bytes32 jobId,bytes32 contractHash,address worker,bytes32 receiptKey,uint8 fault,bytes32 evidence)"
                ),
                j,
                c,
                address(3),
                k,
                uint8(3),
                ev
            )
        );
        bytes32 slash = keccak256(abi.encodePacked("\x19\x01", _domain(address(6)), slashStruct));
        ok(slash == 0xc6dc92800a258588669e0608d11ef1279da9e7bc0d0d6e486ee40224d52cf5bf, "slash digest");
    }

    /// @dev Signatures produced by the Rust signer (`crates/suricomai-attestor`, example
    ///      `reference_signatures`) over the digest above, using private keys 1 to 5. The EVM's own
    ///      `ecrecover` must recover each signer, and each must pass the contract's canonical form
    ///      rules, which is what the contract relies on.
    function test_signatures_made_by_the_rust_signer_recover_and_are_canonical() public view {
        bytes32 digest = 0x305b610578f7ad08d19ed189485e8656c3a42733a4a8de871f057e88e33e9105;
        bytes[5] memory sigs = [
            bytes(
                hex"5212317ef49aa245d431dbec060781136bcfe3d70fc6d273f798ce9e754007325fda8b01a3f7b6e7ad5d899b9e6df2d4a7d0d84c21de4fc17ca94903e3f975541b"
            ),
            bytes(
                hex"608645cb93431a7b79ce5bc9983e7ef2a76691b5d25a75aefc5854978dcdee4d1d9c7965dc53a25b1333ed56d5b03276836d48e194b5e1ce6652594b1856b76f1b"
            ),
            bytes(
                hex"a349e6283524a3822310270f348aec2ea3144a016e3a54d6920498bddb9b0af0701b9edcb7aee45bc4008d8cdbfad3e9ff3cc67fe38166808500dc24a080db811b"
            ),
            bytes(
                hex"1d8b0b06f99b4e5360d7438397904654924bd0fa43472e37c5bdf03eb21dc29d0bfbc8c387b420da09944d5c607efe6f318f7a4ab53a2d066aad66247a58cd661b"
            ),
            bytes(
                hex"fe9f91554a5c461300be9e2ee5408d11f74564cecfb6e814533358545b79641f20ebcfc9c4e277dece6186af987d61ac0f7eb8a1d079721529af6de92df5fb2c1c"
            )
        ];
        uint256 half = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
        for (uint256 i = 0; i < 5; i++) {
            bytes memory sig = sigs[i];
            ok(sig.length == 65, "length");
            bytes32 r;
            bytes32 sValue;
            uint8 v;
            assembly {
                r := mload(add(sig, 32))
                sValue := mload(add(sig, 64))
                v := byte(0, mload(add(sig, 96)))
            }
            ok(v == 27 || v == 28, "v");
            ok(uint256(sValue) <= half, "low s");
            ok(ecrecover(digest, v, r, sValue) == vm.addr(i + 1), "the signer is recovered");
        }
    }

    function test_exactly_the_threshold_and_the_whole_committee_both_work() public {
        esc.settle(id, address(0), _settleSigs(id, P, address(0), T));
        bytes32 two = _bonded("sig2", P, 0);
        esc.settle(two, address(0), _settleSigs(two, P, address(0), N));
    }

    function test_one_short_of_the_threshold_is_refused() public {
        _bad(_settleSigs(id, P, address(0), T - 1));
        _bad(hex"");
    }

    function test_more_signatures_than_members_is_refused() public {
        bytes memory all = _settleSigs(id, P, address(0), N);
        _bad(abi.encodePacked(all, new bytes(65)));
    }

    function test_a_length_that_is_not_a_multiple_of_65_is_refused() public {
        bytes memory good = _settleSigs(id, P, address(0), T);
        _bad(abi.encodePacked(good, hex"00"));
        _bad(_slice(good, 0, good.length - 1));
    }

    function test_a_signer_outside_the_committee_is_refused() public {
        bytes32 digest = _settleDigest(id, P, address(0), address(esc));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBADBAD, digest);
        bytes memory outsider = abi.encodePacked(r, s, v);
        // Whatever the order, a non-member can never count.
        _bad(abi.encodePacked(_sign(digest, 2), outsider));
        _bad(abi.encodePacked(outsider, _sign(digest, 2)));
    }

    function test_a_duplicate_signer_cannot_fill_the_threshold() public {
        bytes32 digest = _settleDigest(id, P, address(0), address(esc));
        bytes memory one = _sign(digest, 1);
        bytes memory two = _sign(digest, 2);
        bytes memory twoSigs = _slice(two, 65, 130);
        _bad(abi.encodePacked(one, one, twoSigs));
        _bad(abi.encodePacked(one, one, one));
    }

    function test_signers_out_of_ascending_order_are_refused() public {
        bytes32 digest = _settleDigest(id, P, address(0), address(esc));
        bytes memory three = _sign(digest, 3);
        bytes memory a = _slice(three, 0, 65);
        bytes memory b = _slice(three, 65, 130);
        bytes memory c = _slice(three, 130, 195);
        _bad(abi.encodePacked(b, a, c));
        _bad(abi.encodePacked(c, b, a));
    }

    function test_a_high_s_signature_is_refused_even_though_it_recovers() public {
        bytes32 digest = _settleDigest(id, P, address(0), address(esc));
        bytes memory good = _sign(digest, T);
        // Flip the first signature into its malleable twin: s becomes n - s and v flips.
        bytes32 s0;
        assembly {
            s0 := mload(add(good, 64))
        }
        bytes32 flippedS = bytes32(CURVE_ORDER - uint256(s0));
        uint8 v0 = uint8(good[64]);
        uint8 flippedV = v0 == 27 ? 28 : 27;
        bytes memory bad = abi.encodePacked(_slice(good, 0, 32), flippedS, flippedV, _slice(good, 65, good.length));
        _bad(bad);
    }

    function test_a_v_value_other_than_27_or_28_is_refused() public {
        bytes memory good = _settleSigs(id, P, address(0), T);
        for (uint8 v = 0; v < 3; v++) {
            bytes memory bad = abi.encodePacked(_slice(good, 0, 64), v, _slice(good, 65, good.length));
            _bad(bad);
        }
        bytes memory v29 = abi.encodePacked(_slice(good, 0, 64), uint8(29), _slice(good, 65, good.length));
        _bad(v29);
    }

    function test_a_signature_that_recovers_to_nothing_is_refused() public {
        bytes memory good = _settleSigs(id, P, address(0), T);
        bytes memory zeroed = abi.encodePacked(new bytes(64), uint8(27), _slice(good, 65, good.length));
        _bad(zeroed);
    }

    function test_signatures_for_a_different_contract_hash_worker_or_key_are_refused() public {
        (,,,,, address worker,, bytes32 ch, bytes32 key) = esc.jobs(id);
        bytes[3] memory sets = [
            _sign(_settleDigestFor(id, keccak256("other"), worker, key, P, address(0), address(esc)), T),
            _sign(_settleDigestFor(id, ch, OTHER, key, P, address(0), address(esc)), T),
            _sign(_settleDigestFor(id, ch, worker, keccak256("other key"), P, address(0), address(esc)), T)
        ];
        for (uint256 i = 0; i < 3; i++) {
            _bad(sets[i]);
        }
    }

    function test_a_signature_cannot_be_moved_to_another_price_or_beneficiary() public {
        // The contract signs for the price it quoted at lock, so a committee cannot attest another.
        bytes memory forOtherPrice = _settleSigs(id, P - 1, address(0), T);
        _bad(forOtherPrice);
        bytes memory forNoRelay = _settleSigs(id, P, address(0), T);
        vm.expectRevert(SuriComAIEscrow.BadSignatures.selector);
        esc.settle(id, RELAY, forNoRelay);
    }

    function test_a_signature_from_another_job_is_refused() public {
        bytes32 other = _bonded("another", P, 100);
        bytes memory forOther = _settleSigs(other, P, address(0), T);
        _bad(forOther);
    }

    function test_a_slash_signature_cannot_pay_and_a_settle_signature_cannot_slash() public {
        bytes memory settleSigs = _settleSigs(id, P, address(0), T);
        vm.expectRevert(SuriComAIEscrow.BadSignatures.selector);
        esc.slash(id, SuriComAIEscrow.Fault.BadQuote, bytes32(uint256(1)), settleSigs);
        bytes memory slashSigs = _sign(_slashDigest(id, 3, bytes32(uint256(1))), T);
        _bad(slashSigs);
    }

    function test_signatures_for_another_contract_or_another_chain_are_refused() public {
        bytes memory otherContract = _sign(_settleDigest(id, P, address(0), address(0xDEAD)), T);
        _bad(otherContract);
        bytes memory thisChain = _settleSigs(id, P, address(0), T);
        vm.chainId(999);
        _bad(thisChain);
        vm.chainId(31337);
    }

    function test_a_slash_needs_the_threshold_too() public {
        bytes32 digest = _slashDigest(id, 3, keccak256("ev"));
        bytes memory few = _sign(digest, T - 1);
        vm.expectRevert(SuriComAIEscrow.BadSignatures.selector);
        esc.slash(id, SuriComAIEscrow.Fault.BadQuote, keccak256("ev"), few);
    }

    function test_a_slash_signature_for_other_evidence_or_fault_is_refused() public {
        bytes memory forEvidence = _sign(_slashDigest(id, 3, keccak256("ev")), T);
        vm.expectRevert(SuriComAIEscrow.BadSignatures.selector);
        esc.slash(id, SuriComAIEscrow.Fault.BadQuote, keccak256("different"), forEvidence);
        vm.expectRevert(SuriComAIEscrow.BadSignatures.selector);
        esc.slash(id, SuriComAIEscrow.Fault.InvalidProof, keccak256("ev"), forEvidence);
    }

    // ------------------------------------------------------------------ util

    function _slice(bytes memory data, uint256 from, uint256 to) private pure returns (bytes memory out) {
        out = new bytes(to - from);
        for (uint256 i = 0; i < out.length; i++) {
            out[i] = data[from + i];
        }
    }
}
