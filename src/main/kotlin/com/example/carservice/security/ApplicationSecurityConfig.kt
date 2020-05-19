package com.example.carservice.security

import com.example.carservice.auth.UserService
import com.example.carservice.jwt.JwtConfig
import com.example.carservice.jwt.JwtTokenVerify
import com.example.carservice.jwt.JwtUsernameAndPasswordAuthenticationFilter
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
@EnableWebSecurity
class ApplicationSecurityConfig(private val passwordEncoder: PasswordEncoder, private val userService: UserService, private val jwtConfig: JwtConfig) : WebSecurityConfigurerAdapter() {

    override fun configure(http: HttpSecurity) {
        http
                .csrf().disable()
                .cors()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig))
                .addFilterAfter(JwtTokenVerify(jwtConfig), JwtUsernameAndPasswordAuthenticationFilter::class.java)
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                //TODO endpoint access and method by role
//                .antMatchers(HttpMethod.DELETE, "/cars/**").hasAnyRole(UserRole.ADMIN.name)
//                .antMatchers(HttpMethod.POST, "/cars/**").hasAnyRole(UserRole.ADMIN.name)
//                .antMatchers(HttpMethod.PUT, "/cars/**").hasAnyRole(UserRole.ADMIN.name)
//                .antMatchers(HttpMethod.GET, "/cars/**").hasAnyRole(UserRole.ADMIN.name, UserRole.USER.name)
                .anyRequest()
                .authenticated()
    }

    override fun configure(auth: AuthenticationManagerBuilder) {
        auth.authenticationProvider(daoAuthProvider())
    }

    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource? {
        val source = UrlBasedCorsConfigurationSource()
        val corsConfiguration = CorsConfiguration()
        corsConfiguration.addExposedHeader("Authorization")
        source.registerCorsConfiguration("/**", corsConfiguration.applyPermitDefaultValues())
        return source
    }

    @Bean
    fun daoAuthProvider(): DaoAuthenticationProvider? {
        val provider = DaoAuthenticationProvider()
        provider.setPasswordEncoder(passwordEncoder)
        provider.setUserDetailsService(userService)
        return provider
    }
}