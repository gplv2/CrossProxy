# cross-proxy
Written by [Glenn Plas](http://byte-consult.be)

 - Uses curl for speed and reliability, not (trying to) re-inventing the wheel.
 - Works with ajax calls that **supports cookies** 
 - Works (for me ) with a RESTful API including PUT and DELETE requests 
 - Works with nginx for php version below 5.4.0 where getallheaders aren't supported natively

## Overview
 - Works around the cross-domain request restrictions 
 - This script tries to do it's best to be a transparant medium
 - Given the above, it does try to do it's best to send it's own http statuses
   in case of problems or missing required input without contacting a backend.
 - Since it has cookie support, it should function for ajax-based logins accross domains 

## Setup
 - crossproxy.php is the class 

$proxy = new CrossProxy(array('http://live.tigerblood.com','dev/backend.php'));
  
CrossProxy class' constructor takes 4 arguments, only the first is required.

1. `$forward_host`, which is where all requests to the proxy will be routed. 
   when this is an array, the second part will be added to the url 
   (invisible to frontend calling the proxy) before calling the backend.
2. `$allowed_hostname`, which an optional parameter. Is this is supplied, it
   should be a hostname or ip address that you would like to restrict requests
   to. It can be an array of hostnames or IPs. 
3. `$handle_errors`, which is a boolean flag with a default value of TRUE. If
   enabled, the object will use it's own error and exception handlers. 
   handling in your application.
4. array of optional options.

## Gotchas

If you are using this proxy and you expect to use cookies, make sure that your
web application is not validating cookies by IP address. This is a common
setting in web frameworks such as CodeIgniter and Kohana which can be easily
disabled. Validations such as cookie-expiration and user-agent are acceptable.

Another gotcha with cookies: Make sure that cookies being emitted from the
target server are going to be accepted by the client.  (cookie domain!)

## Dependencies
   - php curl !

## Inspiration
Don't want to sound too negative, but I tried using others work but I didn't really
like the way it was written, the one that came close was ajax-proxy by 
[Kenny Katzgrau](https://github.com/katzgrau) but that too did things not entirely 
correct.  I tried to fork it and see if I could fix a few things here and there and i
make it work for me, did some merging of a few upstreams but eventually I just wanted 
to rewrite it.  I also didn't want to NOT use curl at all.
This script is for people who have total control over their installs and can install 
curl at will.
Another problem I had with other peoples code was not gracefully erroring out to the 
requester using http status codes.
I did copy over some good idea's too and even code (including docs).  Not all was bad.

## License

Copyright (c) 2012, Byte Consult
All rights reserved.

See included License file
