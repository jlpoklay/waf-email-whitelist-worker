'use strict';

const { WAFV2Client, GetIPSetCommand, UpdateIPSetCommand } = require("@aws-sdk/client-wafv2");
const wafv2 = new WAFV2Client({ region: "us-east-1" });

module.exports.index = async (event) => {
  console.log(JSON.stringify(event))

  const retVal = {
    statusCode: 200,
    body: JSON.stringify(
      {
        message: 'Go Serverless v3.0! Your function executed successfully!',
        input: event,
      },
      null,
      2
    ),
  };

  //Move params somewhere else
  const getParams = {
    Id: 'IP SET ID', /* required - WAF ID */
    Name: 'IP SET NAME', /* required - IP SET NAME */
    Scope: 'REGIONAL', /* required - keep as REGION */
  }

  const { eventName, eventSource, dynamodb } = event?.Records[0];
  if (eventName !== 'REMOVE' && eventSource !== 'aws:dynamodb') return retVal;

  const ipAddress = dynamodb?.Keys?.ipAddress?.S
  const command = new GetIPSetCommand(getParams);
  const getIpSetResponse = await wafv2.send(command);
  const ipSetAddresses = getIpSetResponse?.IPSet?.Addresses;
  const { LockToken } = getIpSetResponse;
  let modifiedIp = isV4Format(ipAddress) ? `${ipAddress}/32` : `${ipAddress}/128`

  const newAddresses = ipSetAddresses.filter(address => address !== modifiedIp)

  if (ipSetAddresses.includes(modifiedIp)) {
    //delete ip from ip set
    const updateCommand = UpdateIPSetCommand({
      Addresses: newAddresses,
      Id: getParams.Id,
      Name: getParams.Name,
      Scope: getParams.Scope,
      LockToken
    })

    await wafv2.send(updateCommand)
  }



  return retVal
};
