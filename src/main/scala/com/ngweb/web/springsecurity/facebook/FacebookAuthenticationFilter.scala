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

import java.io.IOException

import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter

class FacebookAuthenticationFilter
(  
  facebookHelper : FacebookHelper,
  filterProcessUrl : String = FacebookAuthenticationFilter.DEFAULT_FILTER_PROCESS_URL
)
extends AbstractAuthenticationProcessingFilter(filterProcessUrl)
{
  require(facebookHelper != null)
  require(filterProcessUrl != null)
  
  @throws(classOf[AuthenticationException])
  @throws(classOf[IOException])
  @throws(classOf[ServletException])
  override def
  attemptAuthentication
  (
    request : HttpServletRequest,
    response : HttpServletResponse
  ) : Authentication =
  {
    require(request != null)
    require(response != null)
    
    try
    {
      val info = facebookHelper.readFacebookAuthenticationInfo(request)
      
      val token = facebookHelper.makeFacebookAuthenticationToken(info)
      
      token.setDetails(authenticationDetailsSource.buildDetails(request))

      getAuthenticationManager().authenticate(token)
    }
    catch
    {
      case e : FacebookUserNotConnected => 
      throw new AuthenticationCredentialsNotFoundException(
              "Facebook user not connected", e)
    }
  }
}

object FacebookAuthenticationFilter 
{
  val DEFAULT_FILTER_PROCESS_URL = "/j_spring_facebook_security_check"    
}
