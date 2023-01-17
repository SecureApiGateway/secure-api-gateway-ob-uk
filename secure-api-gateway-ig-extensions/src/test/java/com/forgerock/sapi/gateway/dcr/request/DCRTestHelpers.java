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
package com.forgerock.sapi.gateway.dcr.request;

import java.text.ParseException;
import java.util.Map;

import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jws.SignedJwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class DCRTestHelpers {

    public static final String VALID_SSA_FROM_IG = "eyJ0eXAiOiJKV1QiLCJraWQiOiJqd3Qtc2lnbmVyIiwiYWxnIjoiUFMyNTYifQ." +
            "eyJzb2Z0d2FyZV9tb2RlIjoiVEVTVCIsInNvZnR3YXJlX3JlZGlyZWN0X3VyaXMiOiJodHRwczovL3d3dy5nb29nbGUuY29tIiwib3Jn" +
            "X3N0YXR1cyI6IkFjdGl2ZSIsInNvZnR3YXJlX2NsaWVudF9uYW1lIjoiQnJpbmRsZXkgRGFzaGJvYXJkIiwic29mdHdhcmVfY2xpZW50" +
            "X2lkIjoiMTExMTExMTEiLCJpc3MiOiJ0ZXN0LXB1Ymxpc2hlciIsInNvZnR3YXJlX3Rvc191cmkiOiJodHRwczovL215YXBwL3RvcyIs" +
            "InNvZnR3YXJlX2NsaWVudF9kZXNjcmlwdGlvbiI6IkJyaW5kbGV5IEZpbmFuY2lhbCBEYXNoYm9hcmQiLCJzb2Z0d2FyZV9wb2xpY3lf" +
            "dXJpIjoiaHR0cHM6Ly9teWFwcC9wb2xpY3kiLCJzb2Z0d2FyZV9pZCI6InNvZnR3YXJlaWQiLCJvcmdfaWQiOiI1ZjU2M2U4OTc0MmIy" +
            "ODAwMTQ1YzdkYTEiLCJzb2Z0d2FyZV9sb2dvX3VyaSI6Imh0dHBzOi8vYWNtZS1tdXNpYy5jb20vd3AtY29udGVudC91cGxvYWRzLzIw" +
            "MjAvMDcvYWNtZS5wbmciLCJzb2Z0d2FyZV9qd2tzIjp7ImtleXMiOlt7ImQiOiJoUV8yQXB0X3ZCNEVPSGZCZF9wQXVOOEV1U1gyeGNK" +
            "N21HWVNfNGJoMlRKQTVpcWMwRGZNTWVUY3E3QUZGcVhTa0VzYk0xTUJQQldxMTNPR252S3dSbGFoRWk1d0E1Rk5XdnZZN1VxLXJZNkc0" +
            "R2VIRzkxdWVCeW1xSC1oVmhsTURHdzQwT0NTaGJkNU51emVWN0tCZTJkanpqTUxfQTJvYWZWd0I4aUt6TTN2S2lsQUQ1eUNncFJXTExX" +
            "N0tSZFBZSDJJSXRyVzR0Wk93dFZfdzBqLWdqNklzTS1SUkdjM2RqVHpUS1o1QTNFcUlQNkwwbWZjdlpTZzF6ZUVrdC1GZm1MM1pxVExS" +
            "Zkh5aUo0TktHbjFWTXVkRTNnUXJ6VXpDUlBEYnRfclhGYkxmd1o2LUFiY3cwQVVqNWR5X0c2aWZ4SHdWLXdoX3N0d0pJcnh6amJKIiwi" +
            "ZSI6IkFRQUIiLCJ1c2UiOiJ0bHMiLCJraWQiOiIyMDE5NTg5Mjk4MDY0NjI4ODI4OTkzNzcyMTc2MTE4MTYwOTI3IiwieDVjIjpbIk1J" +
            "SUZmekNDQTJlZ0F3SUJBZ0lRQVlUMWNLdG1vNHlYdUxNZ2dTQ2VIekFOQmdrcWhraUc5dzBCQVFzRkFEQW1NU1F3SWdZRFZRUUREQnRV" +
            "WlhOMElGTmxZM1Z5WlNCQ1lXNXJhVzVuSUZKdmIzUWdRMEV3SGhjTk1qTXdNVEUyTVRBME56UTNXaGNOTWpRd01URTJNVEEwTnpRM1dq" +
            "QkVNUlV3RXdZRFZRUUREQXhCWTIxbElFWnBiblJsWTJneEt6QXBCZ05WQkdFTUlsQlRSRWRDTFVaR1FTMDFaalUyTTJVNE9UYzBNbUl5" +
            "T0RBd01UUTFZemRrWVRFd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUNaY1pBNlVDZWFGSGhSUjNmYXlx" +
            "SS9rUCtJUTZ6aHN3aDdRRElMRWxBQUZ5NDhjc0NOcEhQS21XOWFsR1pmVkJQWTdTczhkZHUrWDVsSXlSS0lubGErVFNhR3MxTkFsUjhM" +
            "M0h4d0JEdnQ1YmF5cU5PZWIxTnBrRWhpTU1QWWV2Yngxc3hpSWVPaHhsWm9QbDIyMmNWbFg1QmlzcEdDYS92dEc0RWtBS2tJZWxMSjdB" +
            "aVEyNmRJUCtITHptUk5KUGVwa01nNzNxRW1QTDZMOTNVL2YzU0ZsVDNVdDNqWHQzcWhQVW1rN0FZNE5vRkd5bDM0WUtaMm9RVTl4c0lz" +
            "S1lpaTkwKzJaZjFGV1BxbmExUmUvT1BLblhBMFJqQmVDT0xvQ09QeXVuU3pYVHE2NG40SEMxeWd6Z3ZSSjMydlJxU3U4VFhCcnpqWjk4" +
            "Tk1vajVmZUxjdEFnTUJBQUdqZ2dHSk1JSUJoVEFNQmdOVkhSTUJBZjhFQWpBQU1GWUdBMVVkSXdSUE1FMkFGR0F0blFvUERaRE8vTHNm" +
            "ZTZXR0hZNmw0TFZVb1Nxa0tEQW1NU1F3SWdZRFZRUUREQnRVWlhOMElGTmxZM1Z5WlNCQ1lXNXJhVzVuSUZKdmIzUWdRMEdDQ1FEelpY" +
            "aGdQdGE2Z0RBZEJnTlZIUTRFRmdRVW5FRTZUVmxuelEvd1ltTUVhUThkTnZOMm1iVXdDd1lEVlIwUEJBUURBZ2VBTUJNR0ExVWRKUVFN" +
            "TUFvR0NDc0dBUVVGQndNQ01JSGJCZ2dyQmdFRkJRY0JBd1NCempDQnl6QUlCZ1lFQUk1R0FRRXdFd1lHQkFDT1JnRUdNQWtHQndRQWpr" +
            "WUJCZ013Q1FZSEJBQ0w3RWtCQWpDQm5nWUdCQUNCbUNjQ01JR1RNR293S1FZSEJBQ0JtQ2NCQkF3ZVEyRnlaQ0JDWVhObFpDQlFZWGx0" +
            "Wlc1MElFbHVjM1J5ZFcxbGJuUnpNQjRHQndRQWdaZ25BUU1NRTBGalkyOTFiblFnU1c1bWIzSnRZWFJwYjI0d0hRWUhCQUNCbUNjQkFn" +
            "d1NVR0Y1YldWdWRDQkpibWwwYVdGMGFXOXVEQjFHYjNKblpWSnZZMnNnUm1sdVlXNWphV0ZzSUVGMWRHaHZjbWwwZVF3R1IwSXRSa1pC" +
            "TUEwR0NTcUdTSWIzRFFFQkN3VUFBNElDQVFCRWNsZ1VkZnI2NFM5YmUyMXdSdzBwei93bjR6TWVBWWhSWHUxY3dMd1dRVVNIc1IrU0s1" +
            "emc3cTloTlZ1TnAyKzZBS1lPaG9wblEvUWtNb0FsTXFEa1Y1NFpEK0hybHdCVE92WlRheDRraHRKa1ZuVVA1Yno2K2JTbG1JOUNWQUxm" +
            "aGcrZTdBWnIzUW9rWmp0RmpSOWVIL1I2dkUwTGlxcFNQNHFpYm1OMWgyOGJKVXZ4UGQ4eEIrcWthbGhOT1pCM2JuYm5SazZhTEF1WmhW" +
            "NU5JZ0Y4WVdJWjFhTkhiQk0vN2JPQ0RyL3dLalp4ZkY4NWhwaURWdGlxakEvaTUzY2dzODZwRGNNL3ZOeXc5azJ3V0pLS21yZE8rMU5Y" +
            "VzZGZ1pEL01FVTVzTkZtM0R4azA4REFxMWE0NGhHWEY2OFFtTWJQZ3dtdHowblR3VnEyQXVYWnBtSGNJYmcxT0hoYWhBTlg2KzBJZDdG" +
            "bzZ4MmZOWFNCS3VHbUtCVXp0K2Viem03ZUZVWFZ3cWhVd0NhLzBtcFdoM3pqVXBBbFhxMWI2MVZqaUFOY1pGZ1VLYXc1ZlNMN2Uvd0c2" +
            "cXhWRWVoU1NTUEtSTXJDdThVVG53eWpZTzhYcy9jbnBPWFZIYll0eFBQV3FDVlRSeEo5TTRZcnhac2VMWThUTnFDa0g3YW50VGVnYWNh" +
            "QWlGUGxQWGVIbGNYckEvTWdSeWlMbFhpWXd2ZTdkTTUwUW1Nc2M1VnA5bGI4THhJTitCL0dqWkY1cUoyY1l2a0FXVGp4MFJjLzdQSzNN" +
            "NDFQSmlqRStrRTBzSDlYWkIzNFh4QzhBKzgveXl0ZW9IRlluaE9NSmFBYWdkYXJXVE43YUJKSUhoejE0MENOWUloelhGNVQvejNrQjRw" +
            "MXBETnhNV3c9PSJdLCJkcCI6ImFpYmVXbU5XZURzbmJkWVdoZ3R3dXZWNEJlS2xUY2xFSlg0b2dLdGV5Snl2V2RnX3FZaENMc3Z3X2po" +
            "bUZqSVRKbFAwRHNRMHcwbW5ZcUd6Y1ltVzB3U3NzTjJRMTIyNGlxUnh1d0h1Q3JwZzJ6c0k3Z0NEMVZ6elFXNXFEbGx2RWlMZzZ4clUy" +
            "QVdiMjNJRVJVRk4zaksxU20tZUd1S1BPUW9KZGlwSVJyTSIsImRxIjoiamN5Tkw1cU9mWXJlTnc2Yk1OdTMzTjJVampwSUJ0STFSYnNk" +
            "LV9yeVNYdzNkYVpwRks3TE9wMFhYQndrd1hscmFfZ1Z3d05lQTI3a3NjSllTNFBEbXpCOThXV3B5Tkd2emEza1BYdU1sU0NCTTQ1Z2Jy" +
            "THhVT0F4ZEQ3TFlKbkhyR3EyazZmanJ1dmtQS2o5M2NFbXpRSkl6MnNZSmRmX2F6eXJtdXQ1WHVzIiwibiI6Im1YR1FPbEFubWhSNFVV" +
            "ZDMyc3FpUDVEX2lFT3M0Yk1JZTBBeUN4SlFBQmN1UEhMQWphUnp5cGx2V3BSbVgxUVQyTzByUEhYYnZsLVpTTWtTaUo1V3ZrMG1ock5U" +
            "UUpVZkM5eDhjQVE3N2VXMnNxalRubTlUYVpCSVlqREQySHIyOGRiTVlpSGpvY1pXYUQ1ZHR0bkZaVi1RWXJLUmdtdjc3UnVCSkFDcENI" +
            "cFN5ZXdJa051blNEX2h5ODVrVFNUM3FaRElPOTZoSmp5LWlfZDFQMzkwaFpVOTFMZDQxN2Q2b1QxSnBPd0dPRGFCUnNwZC1HQ21kcUVG" +
            "UGNiQ0xDbUlvdmRQdG1YOVJWajZwMnRVWHZ6anlwMXdORVl3WGdqaTZBamo4cnAwczEwNnV1Si1Cd3Rjb000TDBTZDlyMGFrcnZFMXdh" +
            "ODQyZmZEVEtJLVgzaTNMUSIsInAiOiJ5bm5hYWJWMFM1OUpiemF2Qk5YVHZ0MzYwd290MnVaSmVFOHppdjRjWXg3bDM4dF9sNkVpa21T" +
            "Z3paZFpaQlpGMktOMURJNTBaRVp4dnNFblQ5ZW1SSTdYNjBZaHN4elAwWnFvWmNaTFhKZnVza3VnVDNjb2tZRF8wUXNBUEpYclkxY2hI" +
            "bEN3N29CbnVOX1JjVDJhaURmLTl5WFlxZkVDaWFlRXk4cHV0ZDgiLCJrdHkiOiJSU0EiLCJ4NXQjUzI1NiI6IkRudVJYYmpzcGwyMjBE" +
            "ZkdTSTZEMUpTQ1NtVy00YUhoS0FVNWN5LTJCT00iLCJxIjoid2dHTFlGU2stRmxLemZjV1FhSXdaQk5QdUlIM0pSdHNJY3lfQUtGWS1F" +
            "VDM5M3I3bmoySTBWUlcwZlNwOVl3ZzRzcGJkVi1abUlHTVFXTnVtY2RnajhPQ0NHNW85em9pUm5yUUdGNV96dnpFdHlOZEVTaEtpc2VV" +
            "MWxwT2tjb2Vvb2pkRTV4bUtBYm1nVWxhcGt6b2d5MThIdjhyVjZkUDB4WWxhMEw3ZkhNIiwicWkiOiJIalUtNW9xRGd3OGREbm1XdFBL" +
            "Uy1rSnpsaFk5LWk5UkpGcUVBcGpob3FTN1d3dDA4aG9GYmVXV3ktQjJfaXlha1BlbkxHaU5iUlRuTzRGa1ZPTzlERUw3TmdkRTZySzhP" +
            "M3hpcjAxeGhVRm9EYTlsQU9DQVV1T0dPU1ZHQ0QtdzRKSUpZMDQ1UHV1d0pVX0lhVy1jb3JteEZBem5hRTFERnVtTDdmTUpCSVEiLCJh" +
            "bGciOiJQUzI1NiJ9LHsiZCI6IkdzZGlvMDFMbmplejFNeVFZSmQ5R3NLZXdLLVBOWGRTWkt1ZUM2T0xGRUFLZkt4SHRCWmxESzhzbkpt" +
            "Tm9aLWRBMmVjMFExUkdjTXdpM1RiSlZKLWVwMHg4RlRKd0xOdHJOYS1fZWFLeUdOSlk0X2RGQ3Y2UTkzeGRjcTVQU0pQSjRVM0o5Wmds" +
            "N3U5dU91dlNqcDVfc3RRek5iTW05SjJqYkNvWXhlUl9hOGJEXzhnbFY4WE9ZZ3BrR0FjQVhJY1NoU1ozWU9xUGE0RG5QU3VwcFNQb2hj" +
            "MzBHRkV5Q0s2SmF6dHpieGhRWGhvb25MZ3N3ZWliN1VRV0d3eFNYaUhPYzNzWnNyaVRiNDZTZ1BqeElOV29SUnNWRXVoRC04WlAtb05l" +
            "MUIxbmV2Q1NFVmVyREMzclNYd0pCNFNhZVBBb1hPMWwtTk1ZNEV4OU80M2xiZWRnUSIsImUiOiJBUUFCIiwidXNlIjoic2lnIiwia2lk" +
            "IjoiMTIzNDI3NjYxNjQyMzY4ODExMDQzNjg3ODk0Mjg5NjIyNjk3MTA3IiwieDVjIjpbIk1JSUZmekNDQTJlZ0F3SUJBZ0lRWE50Tmpr" +
            "ZTZlSkpDSHRqR0dxY0VrekFOQmdrcWhraUc5dzBCQVFzRkFEQW1NU1F3SWdZRFZRUUREQnRVWlhOMElGTmxZM1Z5WlNCQ1lXNXJhVzVu" +
            "SUZKdmIzUWdRMEV3SGhjTk1qTXdNVEUyTVRBME56UTJXaGNOTWpRd01URTJNVEEwTnpRMldqQkVNUlV3RXdZRFZRUUREQXhCWTIxbElF" +
            "WnBiblJsWTJneEt6QXBCZ05WQkdFTUlsQlRSRWRDTFVaR1FTMDFaalUyTTJVNE9UYzBNbUl5T0RBd01UUTFZemRrWVRFd2dnRWlNQTBH" +
            "Q1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUR3eVJnTVhHZm1kQkpVRXpId1RwZzdYeVNTNVR1SXo2UnlHbllJdUMvYWpT" +
            "WnpIUVpieEtpYTRJRktwMmVKZytYSmd0Uk9rQ3gwOGtvVjMwOVdZOVlJSXhoNXp3cWMxS1hpT3dBdnhqd2p6ZlFjaEYyMW40Vk1VV1E3" +
            "VjBnalAyVTk4bE5sUjBTY1lTR1QwdHpUdko1VkZ6QzdsdlozNXB1SHRnaWJxZXFZZXVIOGJBMVZkdTMvTmdMaHM4WGVGY2czOEpWRWRQ" +
            "MWhYbWV1cDVxVFBLenRVVVB4S0Qwa2d5R3p5MlZlbDEzN0RlWDIwMUdKcWF4enBqbHpKVEs3N1dCK29jMFp0bzhiWnJ5TElxQkE3bk1q" +
            "YVd1OUhpVjBUWG9RaU9VbTY3RDZCQVBCSTF4OUpXTUZabmtLQ3B0MjRKdWNZVlp0S0owcXREdGxNNkthY1FtckFnTUJBQUdqZ2dHSk1J" +
            "SUJoVEFNQmdOVkhSTUJBZjhFQWpBQU1GWUdBMVVkSXdSUE1FMkFGR0F0blFvUERaRE8vTHNmZTZXR0hZNmw0TFZVb1Nxa0tEQW1NU1F3" +
            "SWdZRFZRUUREQnRVWlhOMElGTmxZM1Z5WlNCQ1lXNXJhVzVuSUZKdmIzUWdRMEdDQ1FEelpYaGdQdGE2Z0RBZEJnTlZIUTRFRmdRVUFK" +
            "M0I3NTlCaWROWndZUzVGL0xEekZhQlIzMHdDd1lEVlIwUEJBUURBZ2VBTUJNR0ExVWRKUVFNTUFvR0NDc0dBUVVGQndNQ01JSGJCZ2dy" +
            "QmdFRkJRY0JBd1NCempDQnl6QUlCZ1lFQUk1R0FRRXdFd1lHQkFDT1JnRUdNQWtHQndRQWprWUJCZ0l3Q1FZSEJBQ0w3RWtCQWpDQm5n" +
            "WUdCQUNCbUNjQ01JR1RNR293S1FZSEJBQ0JtQ2NCQkF3ZVEyRnlaQ0JDWVhObFpDQlFZWGx0Wlc1MElFbHVjM1J5ZFcxbGJuUnpNQjRH" +
            "QndRQWdaZ25BUU1NRTBGalkyOTFiblFnU1c1bWIzSnRZWFJwYjI0d0hRWUhCQUNCbUNjQkFnd1NVR0Y1YldWdWRDQkpibWwwYVdGMGFX" +
            "OXVEQjFHYjNKblpWSnZZMnNnUm1sdVlXNWphV0ZzSUVGMWRHaHZjbWwwZVF3R1IwSXRSa1pCTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElD" +
            "QVFCT0Zsa3E4T2xWcTNFNVlJRVVGd0tYMldKVmF2bWJyTmUyL0dnWkg2VGdwcHUzMlIrKzVLbDUrR015eEFXdytORUMxT2E5WEMyMWpZ" +
            "ZnZYbVFJMEFNWGpFNDdienFaVU1MVVZlZXJsbXlWb3ZTcS8vZWRqMDAvWUM4WXkyd2wzZG43U09IQVV0NGhUVzlhcmIxdTA5VHdPRVVY" +
            "Z01YSXp5TnAxWEpHV2V0UkMvanNvSjNYVWlBdVpzc3ErNlVUZzl3L0Qvc0ZMSzV3cDd6YStEb0F0SThrc2xhWCthdU1vMzhCeUV3aGh3" +
            "K21UQTlYbDQ1ZHl4a0k5TkgvWW0ra3RQYktBV1ZyTXp6TFBaOG5xbGI1M1hQSk5Xd1V6cm5hRWw0VmV6VmNaQ0t6VGNIZmlwZ0xCbDFK" +
            "WTRGbVVOS3FYOFM2NVlVbmd5blNRaHlBakUxYi9uSTYzaEw5bWhzWXJBZWlqcDNsUENNQ1RVbmpkNHhxclk1Rzc5b0ErOVVjNnZaSmNB" +
            "YW5LRnh3NWUxaTR1SWZKY3RYM2xOVGdvKzhMOEZUbUdJMVJvYnE0bkJSWEpjdjFrZHN4eVZURWpEWXp2elljUUcwbkRndU9YZzJZeEV1" +
            "WlFXcG91Z2pQdkdhK0tCb3hzSk4xSkRkOTFJS1VBS3V5bUJVUnZSdWg4OTFOeC95amVTbGVFc1I3cXg4cFBmaWVwNWxyMk1oZ0VjNTNG" +
            "dU1oaWtmc3Qzc3BZNHpoK3ZKWXhQdk5TZG9iRGJEZ3FiaG5iU0ZBSVZmUFNhazJ6UG9SQ25OOUVWaFUxZ1BtV2pMVnhMZlNTc2ZWakI4" +
            "aFQrNVVlM0xFaForYW1MdDFiemRQQlMxU25WTmVxRUhnNzYwNzNVSitBU1daQlJMQlpyUWZ1cGhvNmg1SHc9PSJdLCJkcCI6IkJLZnMx" +
            "ZTRsaGdtVTQwMnJfakZZWHNXZFVud0c5VkdIdkY5YzdOQnFUeUd2dFNxUXFvLXF0R0d2aTJPNHpETy0wbU9pWDBtMlRyUWljSTlxLVRX" +
            "aVRZM0wwQU1xS1o1RkozMU5Odm9ZUGlfazZ0clFJcWF6WlRRMTJueTExUWpBMTdURHN4WmdfclNqWVBwa2dUN0RzOVBuRHRTemN2S19L" +
            "eWJvbVk3a25JYyIsImRxIjoibmdSekM3WjI4SzE2YXJYbEhrMkZma2paWElkMW5vY0tMN2M5cFYzdHdFSkhSd0VocnRTSGZZaFpQdHNz" +
            "OVNKNnhyWlNiTU52MzlqZG95eHBudFBVVTNxb0NvVWZrRmhpWEc1OXN6NFpxa0N2SnhZNkpCMFFzVC1ZbXExd1JmQllyVWJZWmp6dHdY" +
            "WkM1WFhCU2V4ZVBQMThUSkFjSWhUVWVreW9nOVlfektFIiwibiI6IjhNa1lERnhuNW5RU1ZCTXg4RTZZTzE4a2t1VTdpTS1rY2hwMkNM" +
            "Z3YybzBtY3gwR1c4U29tdUNCU3FkbmlZUGx5WUxVVHBBc2RQSktGZDlQVm1QV0NDTVllYzhLbk5TbDRqc0FMOFk4STgzMEhJUmR0Wi1G" +
            "VEZGa08xZElJejlsUGZKVFpVZEVuR0VoazlMYzA3eWVWUmN3dTViMmQtYWJoN1lJbTZucW1IcmhfR3dOVlhidF96WUM0YlBGM2hYSU5f" +
            "Q1ZSSFQ5WVY1bnJxZWFrenlzN1ZGRDhTZzlKSU1oczh0bFhwZGQtdzNsOXROUmlhbXNjNlk1Y3lVeXUtMWdmcUhOR2JhUEcyYThpeUtn" +
            "UU81ekkybHJ2UjRsZEUxNkVJamxKdXV3LWdRRHdTTmNmU1ZqQldaNUNncWJkdUNibkdGV2JTaWRLclE3WlRPaW1uRUpxdyIsInAiOiIt" +
            "WF9KOXY3V3pWM0NwUV80YjZPWkNkVzhub2VHQ2JzbEI0NW1tc0o4UGZWS2ZOQUh4WFd4dVZUQ2VhdmtXb3BkemR1OHlxUUY4cklwbDA4" +
            "OE5PQktXVEVPMGx6NXJNZmFzTU04SWk4a3NMSW5nbG5MLWVVM2MwRG0wWEI0N3lyaWxQUmM2RnowdHQ2OFR4TmIwUFdGNFZzOWZCTzhH" +
            "MEMwYWU3SW9LY1M3VXMiLCJrdHkiOiJSU0EiLCJ4NXQjUzI1NiI6ImgyMmYyMDVCalJ6aEhQMm9SaXkyRUY3SlJjNXVhRl9jUXdqSWN5" +
            "VFJ2QkUiLCJxIjoiOXc4dTR3U1E3dkhoWjA2WUNWa2NTQ0VmdGlHSzBCcTYzU0ZBR1pNbWNsZFlDRTcxbjVxQ3Z1QjE0XzZVLThuamdy" +
            "V05nYi0zNTZ4S1E5MWRQRkdLSXdfYmxVemNhTk5VVVB6MENMNlQ5VEV6OUJaRE5QYTllWnEzTEFwQV9YdEJYVHpDZHBtTXhRdllJVHBN" +
            "ZjRmYnFGaWpHaC1hZkVvaVJfYVdaczJJZVNFIiwicWkiOiJIMTZiWVFEVHNIM2w2dWVoaGhtVjFVQkFfZGpZZjBzOXlPeFgyVDY3Q21W" +
            "UXV6Vm1CNUdHM0MtYS1ROG5aQTB2cm1sckJZZWRrNmhYbnNqWTYwdmxTME9uU0pZQmZSVW5IajBpUXptQ1ZNTEhhQkVQMGRjdFFoUnVE" +
            "S0g0SWJqNk1CMmlKLTJhQlltNENDbHphX2xfV2t5aDE2VXI4YmpsMkQ3c09ocGE3a2ciLCJhbGciOiJQUzI1NiJ9XX0sInNvZnR3YXJl" +
            "X3JvbGVzIjpbIkRBVEEiLCJBSVNQIiwiQ0JQSUkiLCJQSVNQIl0sImV4cCI6MTY3Mzk1Mjg0NSwib3JnX25hbWUiOiJBY21lIEZpbnRl" +
            "Y2giLCJpYXQiOjE2NzM5NTI1NDV9.BiTAcnCPSQVuziVJXY8J15W2_kEbsn0RqYwFCYPjaYAeaCPXJu5d0LKvpgunUrEV9eBwPxQyFy1" +
            "FcHoTeNkJBnnq4ATSBS8AlnY9bi6D0Ur3AyeEBbQyy9bSGakw-mKSspTX8lgDzWPQVUGhmY0wIQYJ_g8bVb-leM9_T-_aiNilFJALF8-" +
            "WPGbsRxnteUc_sF9e6PD_eR80GrGpTaDqMPOdfSK0lUyEEo-eMv0Vm1MByRjINc4qF6ezHv5Vv_ENNOkY0ubKx5x3F9FeZjrYkctTpjB" +
            "U2MCAiH-Kr2zcuLzk0NpGxhMhTibz8ZhKAxTXdQuKLNiI9vaAjeyZOWL-cQ";



    /**
     * Uses nimbusds to create a SignedJWT and returns JWS object in its compact format consisting of
     * Base64URL-encoded parts delimited by period ('.') characters.
     *
     * @param claims      The claims to include in the signed jwt
     * @param signingAlgo the algorithm to use for signing
     * @param jwsSigner   used to signe the jwt
     * @return the jws in its compact form consisting of Base64URL-encoded parts delimited by period ('.') characters.
     */
    public static String createEncodedJwtString(Map<String, Object> claims, JWSAlgorithm signingAlgo, JWSSigner jwsSigner) {
        try {
            final SignedJWT signedJWT = new SignedJWT(new JWSHeader(signingAlgo), JWTClaimsSet.parse(claims));
            signedJWT.sign(jwsSigner);
            return signedJWT.serialize();
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    public static SignedJwt createSignedJwt(Map<String, Object> claims, JWSAlgorithm signingAlgo, JWSSigner jwsSigner) {
        String encodedJwsString = createEncodedJwtString(claims, signingAlgo, jwsSigner);
        return new JwtReconstruction().reconstructJwt(encodedJwsString, SignedJwt.class);
    }
}
