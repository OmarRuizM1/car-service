package com.example.carservice.jwt

import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import java.io.IOException
import java.sql.Date
import java.time.LocalDate
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class JwtUsernameAndPasswordAuthenticationFilter : UsernamePasswordAuthenticationFilter {

    constructor(authenticationManager: AuthenticationManager) : super() {
        this.authenticationManager = authenticationManager
    }

    @Throws(AuthenticationException::class)
    override fun attemptAuthentication(request: HttpServletRequest, response: HttpServletResponse?): Authentication? {
        try {
            val authenticationRequest = ObjectMapper().readValue(request.inputStream, UsernameAndPasswordAuthenticationRequest::class.java)
            val authentication: Authentication = UsernamePasswordAuthenticationToken(authenticationRequest.username, authenticationRequest.password)
            return authenticationManager.authenticate(authentication)
        } catch (e: IOException) {
            throw RuntimeException(e)
        }
    }

    override fun successfulAuthentication(request: HttpServletRequest?, response: HttpServletResponse?, chain: FilterChain?, authResult: Authentication?) {
        //TODO key in propertie
        val key = "securesecuresecuresecuresecuresecuresecuresecuresecuresecuresecure"
        val token: String = Jwts.builder()
                .setSubject(authResult?.name)
                .claim("authorities", authResult?.authorities)
                .setExpiration(Date.valueOf(LocalDate.now().plusWeeks(2)))
                .signWith(Keys.hmacShaKeyFor(key.toByteArray()))
                .compact()
        response?.addHeader("Authorization", "Bearer $token")
    }
}
