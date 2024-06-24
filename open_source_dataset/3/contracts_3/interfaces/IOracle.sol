interface IOracle {
    function getCurrentPrice(address token, uint256 inAmount) external returns (uint256);
    function viewCurrentPrice(address token, uint256 inAmount) external view returns (uint256);
}