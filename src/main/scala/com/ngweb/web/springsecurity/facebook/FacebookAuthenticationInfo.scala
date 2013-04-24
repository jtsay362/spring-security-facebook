package com.ngweb.web.springsecurity.facebook

import java.lang.{Long => JLong}

import net.sf.json.JSONObject

/**
 *
 * @author Jeff
 */
class FacebookAuthenticationInfo
(
  cookies : JSONObject,
  accessTokenMap : Map[String, String]
)
{
  require(cookies != null)
  require(accessTokenMap != null)
  
  private[this] val accessToken : String = 
    accessTokenMap.get("access_token").get

  private[this] val uid : Long = cookies.getLong("user_id")
  
  private[this] val expires : JLong = accessTokenMap.get("expires") match
  {
    case Some(s) => JLong.parseLong(s)
    case _ => null
  }

  def getAccessToken() : String = accessToken

  def getExpires() : JLong = expires

  def getUid() : Long = uid
}
