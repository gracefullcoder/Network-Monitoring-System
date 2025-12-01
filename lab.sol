// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract HealthIoTMonitorClean {

    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    mapping(uint => bool) public devAuth;

    function addDev(uint id) external onlyOwner {
        devAuth[id] = true;
    }

    function delDev(uint id) external onlyOwner {
        devAuth[id] = false;
    }

    modifier authDev(uint id) {
        require(devAuth[id], "Not allowed");
        _;
    }

    struct Data {
        uint hr;
        uint temp;
        uint oxy;
        uint ts;
        uint dev;
    }

    mapping(uint => Data[]) public records;

    event Alert(
        uint pid,
        uint hr,
        uint temp,
        uint oxy,
        uint ts,
        string msg
    );

    uint constant LIM_HR = 180;
    uint constant LIM_OXY = 85;
    uint constant LIM_TEMP = 40;

    function pushData(
        uint devId,
        uint pid,
        uint hr,
        uint temp,
        uint oxy
    ) external authDev(devId) {

        Data memory d = Data(
            hr,
            temp,
            oxy,
            block.timestamp,
            devId
        );

        records[pid].push(d);

        if (hr > LIM_HR) {
            emit Alert(pid, hr, temp, oxy, block.timestamp, "HR_HIGH");
        }
        if (oxy < LIM_OXY) {
            emit Alert(pid, hr, temp, oxy, block.timestamp, "OXY_LOW");
        }
        if (temp > LIM_TEMP) {
            emit Alert(pid, hr, temp, oxy, block.timestamp, "TEMP_HIGH");
        }
    }

    function lastData(uint pid)
        external
        view
        returns (uint hr, uint temp, uint oxy, uint ts, uint dev)
    {
        require(records[pid].length > 0, "None");

        Data memory d = records[pid][records[pid].length - 1];

        return (d.hr, d.temp, d.oxy, d.ts, d.dev);
    }
}
