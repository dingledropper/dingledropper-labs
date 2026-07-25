interface IKiteStakingManager is IStakingManager {
    /**
     * @notice Initiates validator registration with native token stake
     * @param nodeID The node ID of the validator
     * @param blsPublicKey The BLS public key of the validator
     * @param remainingBalanceOwner The P-Chain owner to receive remaining balance on removal
     * @param disableOwner The P-Chain owner that can disable the validator
     * @param delegationFeeBips The fee in basis points for delegations
     * @param minStakeDuration The minimum duration for the stake
     * @param rewardRecipient The address to receive rewards
     * @return validationID The ID of the validation period
     */
    function initiateValidatorRegistration(
        bytes memory nodeID,
        bytes memory blsPublicKey,
        PChainOwner memory remainingBalanceOwner,
        PChainOwner memory disableOwner,
        uint16 delegationFeeBips,
        uint64 minStakeDuration,
        address rewardRecipient
    ) external payable returns (bytes32 validationID);

    /**
     * @notice Initiates delegator registration with native token stake
     * @param validationID The ID of the validator to delegate to
     * @param rewardRecipient The address to receive rewards
     * @return delegationID The ID of the delegation
     */
    function initiateDelegatorRegistration(
        bytes32 validationID,
        address rewardRecipient
    ) external payable returns (bytes32 delegationID);
}

// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: LicenseRef-Ecosystem

pragma solidity 0.8.25;

/**
 * @notice Interface for Validation and Delegation reward calculators
 */
