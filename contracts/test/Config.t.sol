// SPDX-License-Identifier: LicenseRef-SuriComAI-Proprietary
pragma solidity 0.8.28;

import {SuriComAIEscrow} from "../src/SuriComAIEscrow.sol";
import {Fixture} from "./Fixture.sol";

contract ConfigTest is Fixture {
    function _expectBad(SuriComAIEscrow.Config memory c) private {
        vm.expectRevert(SuriComAIEscrow.BadConfig.selector);
        new SuriComAIEscrow(c);
    }

    function test_a_valid_config_deploys() public {
        new SuriComAIEscrow(_config(address(usdc)));
    }

    function test_committee_must_be_sorted_distinct_nonzero_and_not_empty() public {
        SuriComAIEscrow.Config memory c = _config(address(usdc));
        address[] memory empty = new address[](0);
        c.committee = empty;
        _expectBad(c);

        c = _config(address(usdc));
        (c.committee[0], c.committee[1]) = (c.committee[1], c.committee[0]);
        _expectBad(c);

        c = _config(address(usdc));
        c.committee[1] = c.committee[0];
        _expectBad(c);

        c = _config(address(usdc));
        address[] memory withZero = new address[](3);
        withZero[0] = address(0);
        withZero[1] = members[0];
        withZero[2] = members[1];
        c.committee = withZero;
        c.threshold = 2;
        _expectBad(c);

        c = _config(address(usdc));
        address[] memory tooMany = new address[](33);
        for (uint256 i = 0; i < 33; i++) {
            tooMany[i] = address(uint160(i + 1));
        }
        c.committee = tooMany;
        c.threshold = 17;
        _expectBad(c);
    }

    function test_threshold_must_be_a_majority_and_no_more_than_the_committee() public {
        SuriComAIEscrow.Config memory c = _config(address(usdc));
        c.threshold = 2; // not more than half of 5
        _expectBad(c);
        c.threshold = 0;
        _expectBad(c);
        c.threshold = 6;
        _expectBad(c);
        c.threshold = 5;
        new SuriComAIEscrow(c);
    }

    function test_other_parameters_are_validated() public {
        SuriComAIEscrow.Config memory c = _config(address(usdc));
        c.protocolRecipient = address(0);
        _expectBad(c);
        c = _config(address(usdc));
        c.guardian = address(0);
        _expectBad(c);
        c = _config(address(usdc));
        c.userSlashBps = 10_001;
        _expectBad(c);
        c = _config(address(usdc));
        c.capPeriod = 0;
        _expectBad(c);
        c = _config(address(usdc));
        c.startCap = c.maxCap + 1;
        _expectBad(c);
        c = _config(address(usdc));
        c.userCap = 0;
        _expectBad(c);
    }

    function test_the_fee_schedule_is_capped_in_every_build() public {
        SuriComAIEscrow.Config memory c = _config(address(usdc));
        c.protocolBps = esc.MAX_PROTOCOL_BPS() + 1;
        _expectBad(c);
        c = _config(address(usdc));
        c.attestationBps = esc.MAX_ATTESTATION_BPS() + 1;
        _expectBad(c);
        c = _config(address(usdc));
        c.relayBps = esc.MAX_RELAY_BPS() + 1;
        _expectBad(c);
        c = _config(address(usdc));
        c.attestationMin = esc.MAX_ATTESTATION_MIN() + 1;
        _expectBad(c);
        c = _config(address(usdc));
        c.protocolBps = type(uint256).max;
        c.attestationBps = type(uint256).max;
        c.relayBps = type(uint256).max;
        c.attestationMin = type(uint256).max;
        _expectBad(c);
        // Exactly at every cap is allowed.
        c = _config(address(usdc));
        c.protocolBps = esc.MAX_PROTOCOL_BPS();
        c.attestationBps = esc.MAX_ATTESTATION_BPS();
        c.relayBps = esc.MAX_RELAY_BPS();
        c.attestationMin = esc.MAX_ATTESTATION_MIN();
        SuriComAIEscrow capped = new SuriComAIEscrow(c);
        eq(capped.protocolBps(), 300, "protocol at its cap");
        // A zero schedule is allowed: a deployment may charge nothing.
        c = _config(address(usdc));
        c.protocolBps = 0;
        c.attestationBps = 0;
        c.relayBps = 0;
        c.attestationMin = 0;
        SuriComAIEscrow free = new SuriComAIEscrow(c);
        eq(free.quote(1_000_000).total, 1_000_000, "no lines, no charge");
    }

    function test_the_contract_exposes_no_way_to_change_the_committee_or_move_funds() public {
        // The only state-changing calls are the ones in the spec. Probe a few names an
        // upgradeable or administered contract would have, and require that none exist.
        string[6] memory names = [
            "setCommittee(address[])",
            "upgradeTo(address)",
            "sweep(address)",
            "setGuardian(address)",
            "setProtocolRecipient(address)",
            "rescue(address,uint256)"
        ];
        for (uint256 i = 0; i < names.length; i++) {
            (bool called,) = address(esc).call(abi.encodeWithSignature(names[i]));
            ok(!called, names[i]);
        }
    }
}
