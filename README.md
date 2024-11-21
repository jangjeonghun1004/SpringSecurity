# 용어

    인증(Authentication)
    인증은 주체의 신원을 증명하는 과정입니다.

    주체(principal)
    
    크레덴셜(credential)
    신원 증명 정보-주체가 사용자일 경우 크레덴셜은 주로 패스워드입니다.

    인가(Authorization)
    인증을 마친 후 유저에게 부여되는 권한입니다.

# Spring Security

    Spring Security는 모든 HTTP 요청에 서블릿 필터를 적용해 보안을 처리합니다.

    WebSecurityConfigurerAdapter는 Spring Security에서 보안 설정을 구성하기 위해 사용되던 추상 클래스입니다. 
    하지만 Spring Security 5.7부터 더 이상 사용되지 않습니다(Deprecated). 
    대신 "SecurityFilterChain" 빈을 사용하는 방법으로 대체되었습니다.

# SecurityFilterChain

    httpBasic() = HTTP 기본 인증 (HTTP Basic Authentication)
    formLogin() = 사용자가 브라우저에서 로그인 페이지를 통해 인증 정보를 입력하는 방식입니다.
    oauth2Login() = Google, Facebook 등 외부 인증 제공자를 통해 인증을 처리합니다.
    oauth2ResourceServer() = 토큰 기반 인증으로, 클라이언트가 서버로부터 받은 JWT를 요청마다 헤더에 포함해 인증을 수행합니다.
    ldapAuthentication() = 기업 환경에서 주로 사용되며, 디렉터리 서비스(예: Active Directory)를 통한 인증 방식입니다.
    authenticationProvider() = CustomAuthenticationProvider 등을 활용해 직접 인증 로직을 구현할 수 있습니다.
    
    anonymous() = 로그인하지 않은 사용자도 애플리케이션의 일부 리소스에 접근할 수 있도록 허용하거나 특정 권한을 부여할 수 있습니다.
    익명 사용자에게 기본적으로 ROLE_ANONYMOUS 권한을 부여합니다.

    rememberMe() = 특정 기간 동안 인증 상태를 유지하도록 도와주는 기능입니다.
    이 기능은 쿠키 기반으로 동작합니다.

    "formLogin()" 메서드를 호출하면 Spring Security는 다음을 자동으로 설정합니다
    로그인 페이지: 기본 HTML 로그인 페이지를 생성하여 /login 경로에서 제공.
    로그인 처리 URL: 기본적으로 /login 경로에서 로그인 요청을 처리.
    로그인 실패 처리: 실패 시 /login?error로 리다이렉트.
    로그아웃 처리 URL: 기본적으로 /logout 경로에서 로그아웃 처리.

    logout() 메커니즘이 POST 요청에서만 작동하도록 설계되어 있습니다.
    GET 요청은 Cross-Site Request Forgery(CSRF) 공격에 취약하기 때문입니다.
    <form action="<c:url value='/logout' />" method="post"><button>Logout</button></form>

# CSRF

    CSRF(Cross-Site Request Forgery)는 
    사용자가 인증된 세션을 악용하여 원치 않는 작업을 수행하게 하는 보안 취약점입니다.

    Spring Security 5.0 이상에서는 CSRF가 기본적으로 활성화됩니다.
    .csrf(csrf -> csrf.disable()); // CSRF 보호 비활성화
    
    일반 폼(<form>)에서 POST 전송시 "CSRF 토큰"을 함께 전송하지 않으면 
    There was an unexpected error (type=Forbidden, status=403).
    Forbidden(접근 금지) 오류가 발생합니다.

    # CSRF 토큰
    <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>

    하지만
    스프링 폼(<form:form>)에서 POST 전송시에는 "CSRF 토큰"이 자동으로 설정이 됩니다.

# inMemoryAuthentication

    사용자 정보를 애플리케이션 메모리에 저장하는 인증 방식.

# jdbcAuthentication

    RDBMS를 이용한 인증 방식.

    1단계: SecurityConfig 구성
        # SecurityFilterChain 빈(서블릿 필터)
        # AuthenticationManager 빈(인증 관리)
        # PasswordEncoder 빈(암호화)

    2단계: UserDetailsService 구현
        CustomUserDetailsService.java 파일을 참고하세요.

    3단계: 로그인 페이지 생성
        login.jsp 파일을 참고하세요.

    # 추가 정보
        login.jsp에서 POST 전송시 Spring Security가 사용자가 입력한 아이디, 비밀번호를 비교합니다.
        
        만약
        사용자 정의 POST를 처리하고싶다면
        .formLogin(form -> form.disable())로 설정한 후 Controller에서 POST를 구현한다.

    # CustomUserDetailsService가 호출되는 과정
        AuthenticationManager가 인증 요청을 처리:
        사용자가 로그인 폼에서 아이디와 비밀번호를 입력하고 /login으로 POST 요청을 보냅니다.
        AuthenticationManager가 인증 프로세스를 시작합니다.

        Spring Security가 UserDetailsService를 자동으로 사용:
        AuthenticationManager는 CustomUserDetailsService를 호출하여 사용자의 정보를 로드합니다.
        CustomUserDetailsService는 loadUserByUsername() 메서드를 통해 사용자의 아이디, 비밀번호, 권한 등을 반환합니다.
        
        비밀번호 검증:
        loadUserByUsername()에서 반환된 사용자 정보의 비밀번호를 Spring Security가 사용자가 입력한 비밀번호와 비교합니다.
        비밀번호가 일치하면 인증 성공, 그렇지 않으면 실패합니다.
    

