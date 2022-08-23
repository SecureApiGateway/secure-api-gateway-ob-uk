/*
 * Copyright © 2020-2022 ForgeRock AS (obst@forgerock.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import org.forgerock.http.header.ContentTypeHeader
import org.forgerock.openig.util.MessageType
import static org.forgerock.http.protocol.Entity.APPLICATION_JSON_CHARSET_UTF_8

// expected arguments: messageType
def response = new Response(Status.OK)
response.headers[ContentTypeHeader.NAME] = APPLICATION_JSON_CHARSET_UTF_8
if(MessageType.REQUEST.name().equals(messageType.toUpperCase())){
    def entity = request.entity
    logger.info("******** Entity from request: " + entity.getString())
    response.entity = entity.getJson()
    return response
}

// simulation response
def jsonPayload = '{"_id":"AAC_f5a3913a-0299-4169-8f53-0c14e6e90890","_rev":"000000005c8c032e","Data":{"Permissions":["ReadAccountsDetail","ReadBalances"],"ExpirationDateTime":"2019-08-01T00:00:00.000Z","TransactionFromDateTime":"2019-04-03T00:00:00.000Z","TransactionToDateTime":"2019-08-01T00:00:00.000Z","ConsentId": "AAC_f5a3913a-0299-4169-8f53-0c14e6e90890","Status": "AwaitingAuthorisation","CreationDateTime": "2022-08-24T11:56:29.533Z","StatusUpdateDateTime": "2022-08-24T11:56:29.533Z"},"Risk": {}}")'
response.entity = jsonPayload.getBytes()
return response
