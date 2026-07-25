contract RewardVault is Ownable2Step {
    using Address for address payable;
    using SafeERC20 for IERC20;

    /// @notice The address of the staking manager that can distribute rewards
    address public stakingManager;

    /// @notice Emitted when native tokens are deposited
    event Deposited(address indexed sender, uint256 amount);

    /// @notice Emitted when owner withdraws native tokens
    event Withdrawn(address indexed to, uint256 amount);

    /// @notice Emitted when rewards are distributed by the staking manager
    event RewardDistributed(address indexed to, uint256 amount);

    /// @notice Emitted when the staking manager address is updated
    event StakingManagerUpdated(
        address indexed oldManager,
        address indexed newManager
    );

    /// @notice Emitted when ERC20 tokens are rescued
    event ERC20Rescued(
        address indexed token,
        address indexed to,
        uint256 amount
    );

    /// @notice Error thrown when caller is not the staking manager
    error UnauthorizedCaller(address caller);

    /// @notice Error thrown when trying to set zero address
    error ZeroAddress();

    /// @notice Error thrown when trying to withdraw more than balance
    error InsufficientBalance(uint256 requested, uint256 available);

    /// @notice Error thrown when transfer fails
    error TransferFailed();

    /**
     * @notice Constructs the RewardVault contract
     * @param initialOwner The initial owner of the vault
     */
    constructor(address initialOwner) Ownable(initialOwner) {}

    /**
     * @notice Allows anyone to deposit native tokens into the vault
     */
    receive() external payable {
        emit Deposited(msg.sender, msg.value);
    }

    /**
     * @notice Allows anyone to deposit native tokens into the vault
     */
    function deposit() external payable {
        emit Deposited(msg.sender, msg.value);
    }

    /**
     * @notice Sets the staking manager address
     * @param newStakingManager The address of the staking manager
     */
    function setStakingManager(address newStakingManager) external onlyOwner {
        if (newStakingManager == address(0)) {
            revert ZeroAddress();
        }
        address oldManager = stakingManager;
        stakingManager = newStakingManager;
        emit StakingManagerUpdated(oldManager, newStakingManager);
    }

    /**
     * @notice Allows owner to withdraw native tokens from the vault
     * @param to The address to send the tokens to
     * @param amount The amount of tokens to withdraw
     */
    function withdraw(address to, uint256 amount) external onlyOwner {
        if (to == address(0)) {
            revert ZeroAddress();
        }
        if (amount > address(this).balance) {
            revert InsufficientBalance(amount, address(this).balance);
        }
        payable(to).sendValue(amount);
        emit Withdrawn(to, amount);
    }

    /**
     * @notice Allows the staking manager to distribute rewards
     * @param to The address to send the rewards to
     * @param amount The amount of rewards to distribute
     */
    function distributeReward(address to, uint256 amount) external {
        if (msg.sender != stakingManager) {
            revert UnauthorizedCaller(msg.sender);
        }
        if (to == address(0)) {
            revert ZeroAddress();
        }
        if (amount > address(this).balance) {
            revert InsufficientBalance(amount, address(this).balance);
        }
        payable(to).sendValue(amount);
        emit RewardDistributed(to, amount);
    }

    /**
     * @notice Allows owner to rescue ERC20 tokens that were accidentally sent to the vault
     * @param token The address of the ERC20 token to rescue
     * @param to The address to send the tokens to
     * @param amount The amount of tokens to rescue
     */
    function rescueERC20(
        address token,
        address to,
        uint256 amount
    ) external onlyOwner {
        if (token == address(0)) {
            revert ZeroAddress();
        }
        if (to == address(0)) {
            revert ZeroAddress();
        }
        IERC20(token).safeTransfer(to, amount);
        emit ERC20Rescued(token, to, amount);
    }

    /**
     * @notice Returns the current balance of the vault
     * @return The balance in native tokens
     */
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

// SPDX-License-Identifier: LicenseRef-Ecosystem
// (c) 2024, Ava Labs, Inc. All rights reserved.

// modified from https://github.com/ava-labs/icm-contracts/blob/main/contracts/validator-manager/StakingManager.sol

pragma solidity 0.8.25;

import {ValidatorMessages} from "./ValidatorMessages.sol";
import {IValidatorManager} from "./interfaces/IValidatorManager.sol";
import {Delegator, DelegatorStatus, IStakingManager, PoSValidatorInfo, StakingManagerSettings} from "./interfaces/IStakingManager.sol";
import {Validator, ValidatorStatus, PChainOwner} from "./interfaces/IACP99Manager.sol";
import {IRewardCalculator} from "./interfaces/IRewardCalculator.sol";
import {IWarpMessenger, WarpMessage} from "./interfaces/IWarpMessenger.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable@5.0.2/utils/ReentrancyGuardUpgradeable.sol";
import {ContextUpgradeable} from "@openzeppelin/contracts-upgradeable@5.0.2/utils/ContextUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable@5.0.2/access/OwnableUpgradeable.sol";

/**
 * @dev Implementation of the {IStakingManager} interface.
 */
