// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { FHE, euint32, euint8, ebool } from "@fhevm/solidity/lib/FHE.sol";
import { SepoliaConfig } from "@fhevm/solidity/config/ZamaConfig.sol";

contract AnonymousArtAuthentication is SepoliaConfig {

    address public owner;
    uint256 public nextArtworkId;
    uint256 public nextExpertId;

    struct Artwork {
        uint256 id;
        address owner;
        euint32 encryptedMetadata; // Hash of artwork details (age, style, materials)
        euint8 encryptedCondition; // Condition score (0-100)
        bool isSubmitted;
        bool isAuthenticated;
        uint256 submissionTime;
        uint256 authenticationCount;
        uint256 expertConsensus; // Required expert consensus percentage
    }

    struct Expert {
        uint256 id;
        address expertAddress;
        euint8 encryptedCredentials; // Encrypted expertise level
        bool isVerified;
        uint256 authenticationsCompleted;
        uint256 successRate; // Percentage of correct authentications
    }

    struct Authentication {
        uint256 artworkId;
        uint256 expertId;
        euint8 encryptedAuthenticity; // Authenticity score (0-100)
        euint8 encryptedConfidence; // Confidence level (0-100)
        bool isSubmitted;
        uint256 timestamp;
    }

    mapping(uint256 => Artwork) public artworks;
    mapping(uint256 => Expert) public experts;
    mapping(uint256 => mapping(uint256 => Authentication)) public authentications;
    mapping(uint256 => uint256[]) public artworkExperts; // artworkId => expertIds[]

    event ArtworkSubmitted(uint256 indexed artworkId, address indexed owner);
    event ExpertRegistered(uint256 indexed expertId, address indexed expert);
    event AuthenticationSubmitted(uint256 indexed artworkId, uint256 indexed expertId);
    event ArtworkAuthenticated(uint256 indexed artworkId, bool isAuthentic, uint256 finalScore);
    event ExpertVerified(uint256 indexed expertId, address indexed expert);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    modifier onlyVerifiedExpert(uint256 expertId) {
        require(experts[expertId].expertAddress == msg.sender, "Not the expert");
        require(experts[expertId].isVerified, "Expert not verified");
        _;
    }

    modifier artworkExists(uint256 artworkId) {
        require(artworks[artworkId].isSubmitted, "Artwork does not exist");
        _;
    }

    constructor() {
        owner = msg.sender;
        nextArtworkId = 1;
        nextExpertId = 1;
    }

    // Submit artwork for anonymous authentication
    function submitArtwork(
        uint32 _metadataHash,
        uint8 _condition,
        uint256 _requiredConsensus
    ) external returns (uint256) {
        require(_condition <= 100, "Condition must be 0-100");
        require(_requiredConsensus >= 51 && _requiredConsensus <= 100, "Consensus must be 51-100%");

        uint256 artworkId = nextArtworkId++;

        // Encrypt sensitive data
        euint32 encryptedMetadata = FHE.asEuint32(_metadataHash);
        euint8 encryptedCondition = FHE.asEuint8(_condition);

        artworks[artworkId] = Artwork({
            id: artworkId,
            owner: msg.sender,
            encryptedMetadata: encryptedMetadata,
            encryptedCondition: encryptedCondition,
            isSubmitted: true,
            isAuthenticated: false,
            submissionTime: block.timestamp,
            authenticationCount: 0,
            expertConsensus: _requiredConsensus
        });

        // Set ACL permissions
        FHE.allowThis(encryptedMetadata);
        FHE.allowThis(encryptedCondition);
        FHE.allow(encryptedMetadata, msg.sender);
        FHE.allow(encryptedCondition, msg.sender);

        emit ArtworkSubmitted(artworkId, msg.sender);
        return artworkId;
    }

    // Register as an expert (anonymous credentials)
    function registerExpert(uint8 _credentialsHash) external returns (uint256) {
        uint256 expertId = nextExpertId++;

        euint8 encryptedCredentials = FHE.asEuint8(_credentialsHash);

        experts[expertId] = Expert({
            id: expertId,
            expertAddress: msg.sender,
            encryptedCredentials: encryptedCredentials,
            isVerified: false,
            authenticationsCompleted: 0,
            successRate: 0
        });

        // Set ACL permissions
        FHE.allowThis(encryptedCredentials);
        FHE.allow(encryptedCredentials, msg.sender);

        emit ExpertRegistered(expertId, msg.sender);
        return expertId;
    }

    // Owner verifies expert credentials (after private verification)
    function verifyExpert(uint256 expertId) external onlyOwner {
        require(experts[expertId].expertAddress != address(0), "Expert does not exist");
        experts[expertId].isVerified = true;
        emit ExpertVerified(expertId, experts[expertId].expertAddress);
    }

    // Expert submits anonymous authentication
    function submitAuthentication(
        uint256 artworkId,
        uint256 expertId,
        uint8 _authenticity,
        uint8 _confidence
    ) external onlyVerifiedExpert(expertId) artworkExists(artworkId) {
        require(_authenticity <= 100, "Authenticity must be 0-100");
        require(_confidence <= 100, "Confidence must be 0-100");
        require(!authentications[artworkId][expertId].isSubmitted, "Already submitted");

        euint8 encryptedAuthenticity = FHE.asEuint8(_authenticity);
        euint8 encryptedConfidence = FHE.asEuint8(_confidence);

        authentications[artworkId][expertId] = Authentication({
            artworkId: artworkId,
            expertId: expertId,
            encryptedAuthenticity: encryptedAuthenticity,
            encryptedConfidence: encryptedConfidence,
            isSubmitted: true,
            timestamp: block.timestamp
        });

        artworkExperts[artworkId].push(expertId);
        artworks[artworkId].authenticationCount++;
        experts[expertId].authenticationsCompleted++;

        // Set ACL permissions
        FHE.allowThis(encryptedAuthenticity);
        FHE.allowThis(encryptedConfidence);

        emit AuthenticationSubmitted(artworkId, expertId);

        // Check if we have enough authentications for consensus
        _checkConsensus(artworkId);
    }

    // Check if consensus is reached and finalize authentication
    function _checkConsensus(uint256 artworkId) internal {
        Artwork storage artwork = artworks[artworkId];
        if (artwork.authenticationCount < 3) return; // Minimum 3 experts needed

        // Request decryption of all authentications for this artwork
        uint256[] memory expertIds = artworkExperts[artworkId];
        bytes32[] memory cts = new bytes32[](expertIds.length);

        for (uint i = 0; i < expertIds.length; i++) {
            cts[i] = FHE.toBytes32(authentications[artworkId][expertIds[i]].encryptedAuthenticity);
        }

        // Async decryption request
        FHE.requestDecryption(cts, this.processAuthentication.selector);
    }

    // Process authentication results after decryption
    function processAuthentication(
        uint256 requestId,
        uint8[] memory authenticityScores,
        bytes memory signatures
    ) external {
        // Verify signatures - simplified for this implementation
        // In production, implement proper signature verification according to FHE library specs

        // Find the artwork this relates to (simplified - in production use request mapping)
        uint256 artworkId = _findArtworkByRequest(requestId);
        require(artworkId > 0, "Invalid request");

        Artwork storage artwork = artworks[artworkId];
        require(!artwork.isAuthenticated, "Already processed");

        // Calculate consensus
        (bool isAuthentic, uint256 finalScore) = _calculateConsensus(authenticityScores, artwork.expertConsensus);

        artwork.isAuthenticated = true;

        emit ArtworkAuthenticated(artworkId, isAuthentic, finalScore);
    }

    // Calculate consensus from authenticity scores
    function _calculateConsensus(
        uint8[] memory scores,
        uint256 requiredConsensus
    ) internal pure returns (bool isAuthentic, uint256 finalScore) {
        uint256 totalScore = 0;
        uint256 authenticCount = 0;

        for (uint i = 0; i < scores.length; i++) {
            totalScore += scores[i];
            if (scores[i] >= 60) { // Consider 60+ as authentic
                authenticCount++;
            }
        }

        finalScore = totalScore / scores.length;
        uint256 consensusPercent = (authenticCount * 100) / scores.length;

        isAuthentic = consensusPercent >= requiredConsensus && finalScore >= 60;
    }

    // Helper function to find artwork by request (simplified)
    function _findArtworkByRequest(uint256 requestId) internal view returns (uint256) {
        // In production, maintain a mapping of requestId to artworkId
        // This is simplified for demo purposes
        return 1; // Placeholder
    }

    // Get artwork information (public data only)
    function getArtworkInfo(uint256 artworkId) external view returns (
        address artworkOwner,
        bool isSubmitted,
        bool isAuthenticated,
        uint256 submissionTime,
        uint256 authenticationCount,
        uint256 expertConsensus
    ) {
        Artwork storage artwork = artworks[artworkId];
        return (
            artwork.owner,
            artwork.isSubmitted,
            artwork.isAuthenticated,
            artwork.submissionTime,
            artwork.authenticationCount,
            artwork.expertConsensus
        );
    }

    // Get expert public information
    function getExpertInfo(uint256 expertId) external view returns (
        address expertAddress,
        bool isVerified,
        uint256 authenticationsCompleted,
        uint256 successRate
    ) {
        Expert storage expert = experts[expertId];
        return (
            expert.expertAddress,
            expert.isVerified,
            expert.authenticationsCompleted,
            expert.successRate
        );
    }

    // Get experts assigned to artwork
    function getArtworkExperts(uint256 artworkId) external view returns (uint256[] memory) {
        return artworkExperts[artworkId];
    }

    // Update expert success rate (called by owner after verification)
    function updateExpertSuccessRate(uint256 expertId, uint256 newSuccessRate) external onlyOwner {
        require(experts[expertId].expertAddress != address(0), "Expert does not exist");
        require(newSuccessRate <= 100, "Success rate must be 0-100");
        experts[expertId].successRate = newSuccessRate;
    }
}