package com.ngweb.web.springsecurity.facebook

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException

class FacebookAuthenticationProvider extends AuthenticationProvider
{ 
  def
  setUserDetailsService
  (
    userDetailsService : UserDetailsService
  ) : Unit =
  {
    require(userDetailsService != null)

    this.userDetailsService = userDetailsService
  }

  @throws(classOf[AuthenticationException])
  override def
  authenticate
  (
    authentication : Authentication
  ) : Authentication =
  {
		val oldToken = authentication.asInstanceOf[FacebookAuthenticationToken]

    try
    {
      val userDetails = userDetailsService.loadUserByUsername(oldToken.getName())

      val token = new FacebookAuthenticationToken(
          userDetails,
          oldToken.getUid(),
          oldToken.getAccessToken(),
          userDetails.getAuthorities())

      token.setDetails(oldToken.getDetails())
      
      token.setAuthenticated(true)

      token
    }
    catch
    {
      case ex : UsernameNotFoundException => 
        ex.setAuthentication(oldToken)

      throw ex
    }
	}

  override def
	supports
  (
    authentication : Class[_]
  ) : Boolean =
  classOf[FacebookAuthenticationToken].isAssignableFrom(authentication)	

  private[this] var userDetailsService : UserDetailsService = _
}