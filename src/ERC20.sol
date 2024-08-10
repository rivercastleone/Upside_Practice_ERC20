// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ERC20 {
    mapping(address => uint256) private _balances;
    mapping(address => bool) private ownerlist;
    mapping(address => mapping(address => uint256)) private _allowances;
    mapping(address => uint256) private nonce;

    uint256 public _totalSupply;
    string private _name;
    string private _symbol;
    bool private _pause;
    string private version;
    address public owner;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    bytes32 public PERMIT_TYPEHASH =keccak256(
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    constructor(string memory name_, string memory symbol_) {
        owner=msg.sender;
        _pause=false;
        ownerlist[owner] = true;
        _name = name_;
        _symbol = symbol_;
        version='1';
        _totalSupply = 100 * 10 ** decimals();
        _balances[msg.sender] = _totalSupply;
        emit Transfer(address(0), msg.sender, _totalSupply);
    }

    modifier onlyOwner() {
        require(ownerlist[msg.sender]);
        _;
    }
    modifier notPause(){
        require(_pause==false);
        _;
    }

    function totalSupply() public view returns (uint256){
        return _totalSupply;
    }

    function decimals() public pure returns (uint8) {
        return 18;
    }

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }

    function transfer(address to, uint256 amount) public notPause returns (bool) {
        require(_balances[msg.sender] >= amount);
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) public notPause returns (bool) {
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function allowance(address owner, address spender) public view notPause returns (uint256) {
        return _allowances[owner][spender];
    }

    function transferFrom(address from, address to, uint256 amount) public notPause returns (bool) {
        require(_balances[from] >= amount);
        require(_allowances[from][msg.sender] >= amount);

        _balances[from] -= amount;
        _balances[to] += amount;
        _allowances[from][msg.sender] -= amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function addOwner(address addr) private onlyOwner{
        ownerlist[addr]=true;
    }
    function pause() public onlyOwner notPause{
        _pause=!_pause;
    }
    function nonces(address addr) public view returns (uint){
        return nonce[addr];
    }
    
    function _toTypedDataHash(bytes32 structHash) public view returns (bytes32){
        bytes32 result = keccak256(abi.encodePacked(hex"1901",DOMAIN_SEPARATOR(),structHash));
        return result;
    }
    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r,bytes32 s) external {
        require(block.timestamp < deadline);
        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_TYPEHASH,
                owner,
                spender,
                value,
                nonces(owner),
                deadline
            )
        );
        bytes32 hash=_toTypedDataHash(structHash);
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner,"INVALID_SIGNER");
        _allowances[owner][spender] = value;
        nonce[owner]++;

    }
    function v() public view returns(string memory){
        return version;
    }
    
    function DOMAIN_SEPARATOR() internal view returns (bytes32){
    bytes32 separator=keccak256(abi.encode(
        keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
        keccak256('UPSIDE'), 
        keccak256(abi.encode(v())), 
        block.chainid, 
        address(this) 
        ));
        return separator;
    }

    function setVersion(string memory vs) private onlyOwner{
        version=vs;
    }

}