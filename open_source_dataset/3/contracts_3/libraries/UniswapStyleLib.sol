pragma solidity >=0.5.0;

import "@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol";
import "hardhat/console.sol";

abstract contract UniswapStyleLib {
    address public immutable amm1Factory;
    address public immutable amm2Factory;
    address public immutable amm3Factory;
    bytes32 public amm1InitHash;
    bytes32 public amm2InitHash;
    bytes32 public amm3InitHash;
    uint256 public immutable feeBase;

    constructor(
        address _amm1Factory,
        address _amm2Factory,
        address _amm3Factory,
        bytes32 _amm1InitHash,
        bytes32 _amm2InitHash,
        bytes32 _amm3InitHash,
        uint256 _feeBase
    ) {
        amm1Factory = _amm1Factory;
        amm2Factory = _amm2Factory;
        amm3Factory = _amm3Factory;
        amm1InitHash = _amm1InitHash;
        amm2InitHash = _amm2InitHash;
        amm3InitHash = _amm3InitHash;
        feeBase = _feeBase;
    }

    // returns sorted token addresses, used to handle return values from pairs sorted in this order
    function sortTokens(address tokenA, address tokenB)
        internal
        pure
        returns (address token0, address token1)
    {
        require(tokenA != tokenB, "Identical address!");
        (token0, token1) = tokenA < tokenB
            ? (tokenA, tokenB)
            : (tokenB, tokenA);
        require(token0 != address(0), "Zero address!");
    }

    // fetches and sorts the reserves for a pair
    function getReserves(
        address pair,
        address tokenA,
        address tokenB
    ) internal view returns (uint256 reserveA, uint256 reserveB) {
        (address token0, ) = sortTokens(tokenA, tokenB);
        (uint256 reserve0, uint256 reserve1, ) =
            IUniswapV2Pair(pair).getReserves();

        (reserveA, reserveB) = tokenA == token0
            ? (reserve0, reserve1)
            : (reserve1, reserve0);
    }

    // given an input amount of an asset and pair reserves, returns the maximum output amount of the other asset
    function getAmountOut(
        uint256 amountIn,
        uint256 reserveIn,
        uint256 reserveOut
    ) internal view returns (uint256 amountOut) {
        require(amountIn > 0, "INSUFFICIENT_INPUT_AMOUNT");
        require(
            reserveIn > 0 && reserveOut > 0,
            "UniswapV2Library: INSUFFICIENT_LIQUIDITY"
        );
        uint256 amountInWithFee = amountIn * feeBase;
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = reserveIn * 10_000 + amountInWithFee;
        amountOut = numerator / denominator;
    }

    // given an output amount of an asset and pair reserves, returns a required input amount of the other asset
    function getAmountIn(
        uint256 amountOut,
        uint256 reserveIn,
        uint256 reserveOut
    ) internal view returns (uint256 amountIn) {
        require(amountOut > 0, "INSUFFICIENT_OUTPUT_AMOUNT");
        require(
            reserveIn > 0 && reserveOut > 0,
            "UniswapV2Library: INSUFFICIENT_LIQUIDITY"
        );
        uint256 numerator = reserveIn * amountOut * 10_000;

        uint256 denominator = (reserveOut - amountOut) * feeBase;
        amountIn = (numerator / denominator) + 1;
    }

    // performs chained getAmountOut calculations on any number of pairs
    function _getAmountsOut(
        uint256 amountIn,
        bytes32 amms,
        address[] memory tokens
    ) internal view returns (uint256[] memory amounts, address[] memory pairs) {
        require(tokens.length >= 2, "token path too short");

        amounts = new uint256[](tokens.length);
        amounts[0] = amountIn;

        pairs = new address[](tokens.length - 1);

        for (uint256 i; i < tokens.length - 1; i++) {
            address inToken = tokens[i];
            address outToken = tokens[i + 1];

            address pair =
                amms[i] == 0
                    ? pairForAMM1(inToken, outToken)
                    : (amms[i] == 0x01
                       ? pairForAMM2(inToken, outToken)
                       : pairForAMM3(inToken, outToken));
            pairs[i] = pair;

            (uint256 reserveIn, uint256 reserveOut) =
                getReserves(pair, inToken, outToken);

            amounts[i + 1] = getAmountOut(amounts[i], reserveIn, reserveOut);
        }
    }

    // performs chained getAmountIn calculations on any number of pairs
    function _getAmountsIn(
        uint256 amountOut,
        bytes32 amms,
        address[] memory tokens
    ) internal view returns (uint256[] memory amounts, address[] memory pairs) {
        require(tokens.length >= 2, "token path too short");

        amounts = new uint256[](tokens.length);
        amounts[amounts.length - 1] = amountOut;

        pairs = new address[](tokens.length - 1);

        for (uint256 i = tokens.length - 1; i > 0; i--) {
            address inToken = tokens[i - 1];
            address outToken = tokens[i];

            address pair =
                amms[i - 1] == 0
                    ? pairForAMM1(inToken, outToken)
                    : (amms[i -1 ] == 0x01
                       ? pairForAMM2(inToken, outToken)
                       : pairForAMM3(inToken, outToken));
            pairs[i - 1] = pair;

            (uint256 reserveIn, uint256 reserveOut) =
                getReserves(pair, inToken, outToken);
            amounts[i - 1] = getAmountIn(amounts[i], reserveIn, reserveOut);
        }
    }

    // calculates the CREATE2 address for a pair without making any external calls
    function pairForAMM1(address tokenA, address tokenB)
        internal
        view
        returns (address pair)
    {
        (address token0, address token1) = sortTokens(tokenA, tokenB);
        pair = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            hex"ff",
                            amm1Factory,
                            keccak256(abi.encodePacked(token0, token1)),
                            amm1InitHash
                        )
                    )
                )
            )
        );
    }

    function pairForAMM2(address tokenA, address tokenB)
        internal
        view
        returns (address pair)
    {
        (address token0, address token1) = sortTokens(tokenA, tokenB);
        pair = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            hex"ff",
                            amm2Factory,
                            keccak256(abi.encodePacked(token0, token1)),
                            amm2InitHash
                        )
                    )
                )
            )
        );
    }

    function pairForAMM3(address tokenA, address tokenB)
        internal
        view
        returns (address pair)
    {
        (address token0, address token1) = sortTokens(tokenA, tokenB);
        pair = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            hex"ff",
                            amm3Factory,
                            keccak256(abi.encodePacked(token0, token1)),
                            amm3InitHash
                        )
                    )
                )
            )
        );
    }
}
