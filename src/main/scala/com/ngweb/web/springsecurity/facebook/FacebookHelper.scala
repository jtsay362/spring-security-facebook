/*
 * Copyright [2009] [Kadir PEKEL]
 * 
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.ngweb.web.springsecurity.facebook

import java.net.URI

import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import scala.collection.JavaConversions._
import scala.collection.mutable

import org.slf4j.LoggerFactory
import org.slf4j.Logger

import org.apache.commons.codec.binary.Base64

import org.apache.http.HttpResponse
import org.apache.http.client.ResponseHandler
import org.apache.http.client.utils.URIUtils
import org.apache.http.conn.ClientConnectionManager
import org.apache.http.entity.StringEntity
import org.apache.http.impl.client.ContentEncodingHttpClient
import org.apache.http.message.BasicHttpEntityEnclosingRequest
import org.apache.http.message.BasicHttpRequest
import org.apache.http.params.BasicHttpParams
import org.apache.http.protocol.BasicHttpContext
import org.apache.http.util.EntityUtils

import net.sf.json.JSONObject

class FacebookHelper
(
  appId : String,
  apiKey : String,
  secret : String,
  connectionManager : ClientConnectionManager
)
{
  require(appId != null)
  require(apiKey != null)
  require(secret != null)
  require(connectionManager != null)
  
  import FacebookHelper._
  
  def
  readFacebookAuthenticationInfo
  (
    request : HttpServletRequest
  ) : FacebookAuthenticationInfo =
  {
    require(request != null)

    val cookieData = parseFacebookParametersFromCookies(request)
    val accessTokenMap = exchangeCodeForAccessToken(
      cookieData.getString("code"))
    
    new FacebookAuthenticationInfo(cookieData, accessTokenMap)    
  }
  
  def
  makeFacebookAuthenticationToken
  (
    info : FacebookAuthenticationInfo    
  ) : FacebookAuthenticationToken =
  {
    require(info != null)
    
    new FacebookAuthenticationToken(info.getUid(), info.getAccessToken())
  }    

  private[this] def
  parseFacebookParametersFromCookies
  (
    request : HttpServletRequest
  ) : JSONObject =
  {
		val cookies = request.getCookies()
    
		if (cookies == null)
    {
      throw new RuntimeException("No cookies found")
    }

    val prefix = "fbsr_" + appId
		for (cookie <- cookies)
    {
      val name = cookie.getName
      if ((name != null) && name.startsWith(prefix))
      {
        cookie.getValue.split('.') match
        {
          case Array(hash, payload) =>
          {
            val data = new String(base64UrlDecode(payload), "UTF-8")                        
            val retval = JSONObject.fromObject(data)
            
            if (verifySignature(payload, hash, retval.getString("algorithm")))
            {              
              return retval
            }
            else
            {
              logger.warn("Signature doesn't match!")
            }
          }
          
          case _ =>  
        }
      }
    }
    
		throw new RuntimeException("No facebook cookies found")
  }

  private[this] def
  exchangeCodeForAccessToken
  (
    code : String
  ) : Map[String, String] =
  {
    val httpClient = new ContentEncodingHttpClient(connectionManager, 
      new BasicHttpParams())

    val request = new BasicHttpEntityEnclosingRequest("POST", ACCESS_TOKEN_URL)
    
    request.setHeader("Content-Type", URL_ENCODED_MIME_TYPE)
    
    val body = "client_id=" + appId + "&client_secret=" + secret + 
      "&redirect_uri=&code=" + code
        
    request.setEntity(new StringEntity(body))    
    
    httpClient.execute(ACCESS_TOKEN_HOST, request, 
      new ResponseHandler[Map[String, String]] 
      {
        override def
        handleResponse
        (
          response : HttpResponse
        ) : Map[String, String] = 
        {          
          val dataMap = response.getStatusLine.getStatusCode match
          {
            case 200 =>
            {
              val m = new mutable.HashMap[String, String]()
                
              Option(response.getEntity).foreach(entity => 
              {
                try
                {
                  val responseBody = EntityUtils.toString(entity)
                  
                  val parts = responseBody.split('&')
                  
                  for (part <- parts)    
                  {
                    part.split('=') match
                    {
                      case Array(name, value) => m.put(name, value)                          
                      case _ => logger.warn("Unrecognized part: '" + part + "'")   
                    }                                                                
                  }                                                                  
                }
                finally
                {
                  EntityUtils.consume(entity)
                }
              })               
            
              m  
            }
            
            case responseCode => throw new RuntimeException(
              "Can't exchange code for access token, status = " + responseCode)  
          }

          dataMap.toMap
        }
      },
      new BasicHttpContext()
    )    
  }

  private[this] def
  verifySignature
  (
    payload : String,
    hash : String,
    algorithm : String
  ) : Boolean =
  {
    algorithm match 
    {
      case "HMAC-SHA256" =>
      {
        val mac = Mac.getInstance("HmacSHA256")                
        val sks = new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256")
        
        mac.init(sks)          
        val digest = mac.doFinal(payload.getBytes("UTF-8"))
        
        val signature = base64UrlDecode(hash)
        
        signature.sameElements(digest)            
      }
              
      case _ => 
      {
        logger.warn("Unknown hashing algorithm: '" + algorithm + "'")
        false
      }   
    }
  }      
      
  private[this] val httpParams = new BasicHttpParams()  
}

object FacebookHelper
{
  private def 
  base64UrlDecode
  (
    s : String
  ) : Array[Byte] =
  Base64.decodeBase64(s.replace('-', '+').replace('_', '/'))      

  val ACCESS_TOKEN_URL = "https://graph.facebook.com/oauth/access_token"  
  
  val ACCESS_TOKEN_HOST = URIUtils.extractHost(new URI(ACCESS_TOKEN_URL))        
  
  val URL_ENCODED_MIME_TYPE = "application/x-www-form-urlencoded"
  
  private val logger = LoggerFactory.getLogger(classOf[FacebookHelper])
}
