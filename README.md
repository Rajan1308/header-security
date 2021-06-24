# header-security
Header Security through htaccess

# Check your website headers here: https://www.serpworx.com/check-security-headers/ or https://gf.dev/
# This configuration works for WP, WC on LiteSpeed server. Be careful. Test site after installing. All lines are explained are in serpworx.com tester.

# More docs:
# https://www.netsparker.com/whitepaper-http-security-headers/#XFrameOptionsHTTPHeader
# https://owasp.org/www-project-secure-headers/
# https://www.keycdn.com/blog/http-security-headers

# Main security options in .htaccess file:

# BEGIN security
<IfModule mod_headers.c>
    Header set Age "216000"
    Header set X-Frame-Options SAMEORIGIN #arba DENY
    Header set X-XSS-Protection "1; mode=block"
    Header set X-Content-Type-Options "nosniff"
    Header set X-Permitted-Cross-Domain-Policies "none"
    Header set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" env=HTTPS
    #Header set Content-Security-Policy "default-src * data:; script-src https: 'unsafe-inline' 'unsafe-eval'; style-src https: 'unsafe-inline'"
    #Header set Content-Security-Policy "default-src 'self'; script-src https: 'unsafe-inline'; img-src https: data: 'unsafe-inline'; style-src https: 'unsafe-inline'; object-src 'none'; child-src 'self'; frame-ancestors 'none'; frame-src 'self' *.hotjar.com; connect-src 'self' *.hotjar.com; base-uri 'self';form-action 'self'; font-src https: data: 'self' *.fontawesome.com; upgrade-insecure-requests; block-all-mixed-content"
    Header set Content-Security-Policy "default-src 'self' data:; object-src 'none'; child-src 'self'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content"
    Header set Referrer-Policy "no-referrer-when-downgrade"
    Header set Feature-Policy "accelerometer 'none'; ambient-light-sensor 'self'; autoplay 'self'; camera 'none'; cookie 'self'; docwrite 'self'; domain 'self'; encrypted-media 'self'; fullscreen 'self'; geolocation 'none'; gyroscope 'none'; magnetometer 'none'; microphone 'none'; midi 'none'; payment 'self'; picture-in-picture 'self'; speaker 'self'; sync-script 'self'; sync-xhr 'self'; unsized-media 'self'; usb 'none'; vertical-scroll 'self'; vibrate 'none'; vr 'none'"
    Header set Permissions-Policy "accelerometer=Origin(), autoplay=(), camera=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), publickey-credentials-get=(), usb=()"
    Header set Expect-CT: enforce, max-age=31536000 #this couses 500 problems often with WP
    Header always unset X-Powered-By
    Header always unset server
    Header unset X-Powered-By
    Header unset server
    Header append Vary "Accept-Encoding, User-Agent, Referer"
</IfModule>
# END BEGIN security
