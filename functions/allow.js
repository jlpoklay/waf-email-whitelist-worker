'use strict';

const merge = require('lodash.merge');
const moment = require('moment');
const {isV4Format, isV6Format} = require('ip');
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const {  DynamoDBDocumentClient, GetCommand, PutCommand, UpdateCommand } = require("@aws-sdk/lib-dynamodb");
const { WAFV2Client, GetIPSetCommand, UpdateIPSetCommand } = require("@aws-sdk/client-wafv2");
const wafv2 = new WAFV2Client({ region: "us-east-1" });

const client = new DynamoDBClient({ region: 'us-east-1'});
const ddbDocClient = DynamoDBDocumentClient.from(client);
const tableName = 'ip-whitelist'

const ipRegex = /(?<=\[\[\[)(.*?)(?=\]\]\])/g

module.exports.index = async (event) => {
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


  const command = new GetIPSetCommand(getParams);
  const getIpSetResponse = await wafv2.send(command);

  const parsedEvent = await JSON.parse(event?.Records[0]?.body);
  const { mail, content } = parsedEvent;
  //Add checks for email source
  const { source } = mail;
  const decodedContent = Buffer.from(content, 'base64').toString('ascii');
  //Get only last address from match
  //TODO - clean this: change it to first occurence
  const ipAddress = [...decodedContent.matchAll(ipRegex)].map(item => item[0])[0];
  let modifiedIp;
  if (isV4Format(ipAddress)) {
    modifiedIp = `${ipAddress}/32`
  } else if (isV6Format(ipAddress)) {
    modifiedIp = `${ipAddress}/128`
  } else {
    //end process without doing anything
    return retVal
  }

  const ipSetAddresses = getIpSetResponse?.IPSet?.Addresses;
  const { LockToken } = getIpSetResponse;

  if (!ipSetAddresses.includes(modifiedIp)) {
    //If ip does not exist in ip set add to dynamo and ip set
    ipSetAddresses.push(modifiedIp)
    const updateParams = merge({ Addresses: ipSetAddresses, LockToken }, getParams);
    const updateCommand = new UpdateIPSetCommand(updateParams);
    await wafv2.send(updateCommand);
    await ddbDocClient.send( new PutCommand({
      TableName: tableName,
      Item: {
        ipAddress,
        email: source,
        ttl: `${moment().add(7, 'days').unix()}`
      }
    }))
  } else {
    //If ip does exist, just refresh/update ip's ttl in dynamo
    const updated = await ddbDocClient.send( new UpdateCommand(
      {
        TableName: tableName,
        Key: {
          ipAddress
        },
        UpdateExpression: `SET #T = :ttl, email = :email`,
        ExpressionAttributeValues: {
          ':ttl': moment().add(7, 'days').unix(),
          ':email': source
        },
        ExpressionAttributeNames: {
          '#T': 'ttl' 
        }
      }
    ))
    console.log('UPDATED: ' + updated)
  }

  return retVal
};
