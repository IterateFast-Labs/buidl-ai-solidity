// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.3.0) (governance/IGovernor.sol)

// >>> FISSION MOD
// Example modifications for AI-based voting, reason logging, etc.

pragma solidity ^0.8.20;

import {IERC165} from "../interfaces/IERC165.sol";
import {IERC6372} from "../interfaces/IERC6372.sol";

/**
 * @dev Interface of the {Governor} core.
 *
 * NOTE: Some new functions/events below demonstrate how you might incorporate
 * AI-specific operations. Original OpenZeppelin declarations remain intact.
 */
interface IGovernor is IERC165, IERC6372 {
    enum ProposalState {
        Pending,
        Active,
        Canceled,
        Defeated,
        Succeeded,
        Queued,
        Expired,
        Executed
    }

    // -------------------------------------------------------------------------
    // Original OpenZeppelin errors (unchanged)
    // -------------------------------------------------------------------------
    error GovernorInvalidProposalLength(uint256 targets, uint256 calldatas, uint256 values);
    error GovernorAlreadyCastVote(address voter);
    error GovernorDisabledDeposit();
    error GovernorOnlyExecutor(address account);
    error GovernorNonexistentProposal(uint256 proposalId);
    error GovernorUnexpectedProposalState(uint256 proposalId, ProposalState current, bytes32 expectedStates);
    error GovernorInvalidVotingPeriod(uint256 votingPeriod);
    error GovernorInsufficientProposerVotes(address proposer, uint256 votes, uint256 threshold);
    error GovernorRestrictedProposer(address proposer);
    error GovernorInvalidVoteType();
    error GovernorInvalidVoteParams();
    error GovernorQueueNotImplemented();
    error GovernorNotQueuedProposal(uint256 proposalId);
    error GovernorAlreadyQueuedProposal(uint256 proposalId);
    error GovernorInvalidSignature(address voter);
    error GovernorUnableToCancel(uint256 proposalId, address account);

    // -------------------------------------------------------------------------
    // Original OpenZeppelin events (unchanged)
    // -------------------------------------------------------------------------
    event ProposalCreated(
        uint256 proposalId,
        address proposer,
        address[] targets,
        uint256[] values,
        string[] signatures,
        bytes[] calldatas,
        uint256 voteStart,
        uint256 voteEnd,
        string description
    );
    event ProposalQueued(uint256 proposalId, uint256 etaSeconds);
    event ProposalExecuted(uint256 proposalId);
    event ProposalCanceled(uint256 proposalId);

    event VoteCast(
        address indexed voter,
        uint256 proposalId,
        uint8 support,
        uint256 weight,
        string reason
    );
    event VoteCastWithParams(
        address indexed voter,
        uint256 proposalId,
        uint8 support,
        uint256 weight,
        string reason,
        bytes params
    );

    // -------------------------------------------------------------------------
    // >>> FISSION MOD: New events for AI delegate logic
    // -------------------------------------------------------------------------
    /**
     * @dev Emitted when the governor assigns or updates the designated AI delegate.
     */
    event AIDelegateSet(address indexed oldDelegate, address indexed newDelegate);

    /**
     * @dev Emitted when an AI delegate casts a vote with a given confidence score
     *      and an AI-generated reasoning string.
     */
    event AIVoteCast(
        uint256 indexed proposalId,
        address indexed voter,
        uint8 support,
        uint256 weight,
        uint256 confidence,
        string reasoning
    );

    // -------------------------------------------------------------------------
    // Original OpenZeppelin getters
    // -------------------------------------------------------------------------
    function name() external view returns (string memory);
    function version() external view returns (string memory);
    // solhint-disable-next-line func-name-mixedcase
    function COUNTING_MODE() external view returns (string memory);

    function hashProposal(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) external pure returns (uint256);

    function getProposalId(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) external view returns (uint256);

    function state(uint256 proposalId) external view returns (ProposalState);

    function proposalThreshold() external view returns (uint256);

    function proposalSnapshot(uint256 proposalId) external view returns (uint256);

    function proposalDeadline(uint256 proposalId) external view returns (uint256);

    function proposalProposer(uint256 proposalId) external view returns (address);

    function proposalEta(uint256 proposalId) external view returns (uint256);

    function proposalNeedsQueuing(uint256 proposalId) external view returns (bool);

    function votingDelay() external view returns (uint256);

    function votingPeriod() external view returns (uint256);

    function quorum(uint256 timepoint) external view returns (uint256);

    function getVotes(address account, uint256 timepoint) external view returns (uint256);

    function getVotesWithParams(
        address account,
        uint256 timepoint,
        bytes memory params
    ) external view returns (uint256);

    function hasVoted(uint256 proposalId, address account) external view returns (bool);

    function propose(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory description
    ) external returns (uint256 proposalId);

    function queue(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) external returns (uint256 proposalId);

    function execute(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) external payable returns (uint256 proposalId);

    function cancel(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) external returns (uint256 proposalId);

    function castVote(uint256 proposalId, uint8 support) external returns (uint256 balance);

    function castVoteWithReason(
        uint256 proposalId,
        uint8 support,
        string calldata reason
    ) external returns (uint256 balance);

    function castVoteWithReasonAndParams(
        uint256 proposalId,
        uint8 support,
        string calldata reason,
        bytes memory params
    ) external returns (uint256 balance);

    function castVoteBySig(
        uint256 proposalId,
        uint8 support,
        address voter,
        bytes memory signature
    ) external returns (uint256 balance);

    function castVoteWithReasonAndParamsBySig(
        uint256 proposalId,
        uint8 support,
        address voter,
        string calldata reason,
        bytes memory params,
        bytes memory signature
    ) external returns (uint256 balance);

    // -------------------------------------------------------------------------
    // >>> FISSION MOD: New AI-specific function declarations
    // -------------------------------------------------------------------------

    /**
     * @dev Returns the address of the current AI delegate (if any).
     */
    function aiDelegate() external view returns (address);

    /**
     * @dev Set or update the AI delegate address. Typically restricted by `onlyGovernance`.
     *
     * Emits a {AIDelegateSet} event.
     */
    function setAIDelegate(address newDelegate) external;

    /**
     * @dev Let the AI delegate cast a vote with an additional confidence parameter
     *      and an AI reasoning string, stored for future reference.
     *
     * Emits an {AIVoteCast} event.
     */
    function castAIVote(
        uint256 proposalId,
        uint8 support,
        uint256 confidence,
        string calldata aiReason
    ) external returns (uint256 balance);

    /**
     * @dev Retrieve the last known AI confidence score for a given proposal (if any).
     */
    function getAIConfidence(uint256 proposalId) external view returns (uint256);

    /**
     * @dev Retrieve the AI reason log (text) associated with a proposal (if any).
     */
    function getAIReasonLog(uint256 proposalId) external view returns (string memory);
}
