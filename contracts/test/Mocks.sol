// SPDX-License-Identifier: LicenseRef-SuriComAI-Proprietary
pragma solidity 0.8.28;

/// @dev A plain 6-decimal token. `blocked` addresses cannot send or receive, like a frozen account.
contract MockUSDC {
    string public name = "Mock USD Coin";
    uint8 public decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public blocked;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function block_(address who, bool value) external {
        blocked[who] = value;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) public virtual returns (bool) {
        _move(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public virtual returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "allowance");
        allowance[from][msg.sender] = allowed - amount;
        _move(from, to, amount);
        return true;
    }

    function _move(address from, address to, uint256 amount) internal virtual {
        require(!blocked[from] && !blocked[to], "blocked");
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

/// @dev Takes one percent of every transfer, like a fee-on-transfer token.
contract FeeToken is MockUSDC {
    function _move(address from, address to, uint256 amount) internal override {
        require(balanceOf[from] >= amount, "balance");
        uint256 fee = amount / 100;
        balanceOf[from] -= amount;
        balanceOf[to] += amount - fee;
    }
}

/// @dev Returns nothing from transfer and transferFrom, like some older tokens.
contract NoReturnToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
    }

    function transfer(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }

    function transferFrom(address from, address to, uint256 amount) external {
        require(allowance[from][msg.sender] >= amount, "allowance");
        require(balanceOf[from] >= amount, "balance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

/// @dev Says false instead of reverting, and moves nothing.
contract FalseToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address, uint256) external pure returns (bool) {
        return true;
    }

    function transfer(address, uint256) external pure returns (bool) {
        return false;
    }

    function transferFrom(address, address, uint256) external pure returns (bool) {
        return false;
    }
}

/// @dev Calls back into the escrow while it is pulling funds. The test records what happened.
contract ReentrantToken is MockUSDC {
    address public target;
    bytes public attack;
    bool public attacked;
    bool public attackSucceeded;
    bytes public attackResult;

    function arm(address target_, bytes calldata attack_) external {
        target = target_;
        attack = attack_;
        attacked = false;
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        if (target != address(0) && !attacked) {
            attacked = true;
            (bool ok, bytes memory ret) = target.call(attack);
            attackSucceeded = ok;
            attackResult = ret;
        }
        return super.transferFrom(from, to, amount);
    }
}

/// @dev Answers every call except `balanceOf` with `len` bytes of 0x01, to test return-data handling.
contract WeirdReturnToken {
    uint256 public len;

    function setLen(uint256 value) external {
        len = value;
    }

    function balanceOf(address) external pure returns (uint256) {
        return 0;
    }

    fallback() external {
        uint256 n = len;
        assembly {
            let out := mload(0x40)
            for { let i := 0 } lt(i, n) { i := add(i, 1) } { mstore8(add(out, i), 1) }
            return(out, n)
        }
    }
}
