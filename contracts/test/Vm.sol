// SPDX-License-Identifier: LicenseRef-SuriComAI-Proprietary
pragma solidity 0.8.28;

/// @dev The few Foundry cheatcodes the tests use, declared here so the project has no
///      third-party Solidity dependency.
interface Vm {
    function warp(uint256 newTimestamp) external;
    function chainId(uint256 newChainId) external;
    function prank(address caller) external;
    function startPrank(address caller) external;
    function stopPrank() external;
    function expectRevert(bytes4 selector) external;
    function expectRevert() external;
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
}
