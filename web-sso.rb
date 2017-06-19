require 'net/http'
require 'http-cookie'
require 'nokogiri'
require 'json'
require 'sinatra'

# Sinatra / Puma config
set :server, :puma
set :environment, :production

# Store uris
$wikiUri = URI("https://tepid.science.mcgill.ca/wiki/index.php/Special:UserLogin")
$tepidUri = URI("http://tepid.science.mcgill.ca/tepid/sessions/")
$gitblitUri = URI("http://git.sus.mcgill.ca:8080/gitblit/")
$gitblitQUri = URI("http://git.sus.mcgill.ca:8080/gitblit/?wicket:interface=:1:userPanel:loginForm::IFormSubmitListener::")


def wikiAuth(uri, user, pass, params=nil)
	# Authenticate with Mediawiki
	# Hold cookies
	cookieJar = HTTP::CookieJar.new
	# Get a session cookie from Mediawiki
	res = Net::HTTP.get_response(uri)
	res.get_fields('Set-Cookie').each do |value|
		cookieJar.parse(value,uri)
	end
	
	# Parse HTML to find login token embedded in login form
	page = Nokogiri::HTML(res.body)
	loginToken = page.css('input[name=wpLoginToken]').first['value']

	# POST data to login page, simulating a user interaction
	Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
		req = Net::HTTP::Post.new uri
		req.form_data = { wpName: user, wpPassword: pass, wploginattempt: 'Log+in', wpEditToken: '+\\', title: 'Special:userLogin', authAction: 'login', force: '', wpLoginToken: loginToken } 
		# Send session cookie back to Mediawiki
		req['Cookie'] = HTTP::Cookie.cookie_value(cookieJar.cookies(uri))
		res = http.request req
		# Signal failure if we didn't get a redirect request
		return nil if res.code.to_i == 200
		# Store cookies to forward to user
		res.get_fields('Set-Cookie').each do |value|
			cookieJar.parse(value, uri)
		end
	end
	return cookieJar
end

def tepidAuth(uri, user, pass)
	# Authenticate with TEPID
	
	resJson = nil
	# POST credentials JSON to TEPID Tomcat, simulating client-side js auth
	Net::HTTP.start(uri.host, 8443, use_ssl: true) do |http|
		req = Net::HTTP::Post.new(uri, "Content-Type" => 'application/json;charset=utf-8', "Accept" => 'application/json, text/plain, */*')
		req.body = JSON.generate({username: user, password: pass, persistent: false})
		res = http.request req
		# Signal failure on bad HTTP Status code
		return nil if res.code.to_i != 200
		# Store JSON with user information to forward to user
		resJson = res.body
	end
	return resJson
end

def gitblitAuth(uri, user, pass, params = nil)
	# Authenticate with Gitblit
	# Hold cookies
	cookieJar = HTTP::CookieJar.new
	# Get a session cookie from Gitblit
	res = Net::HTTP.get_response(uri)
	res.get_fields('Set-Cookie').each do |value|
		cookieJar.parse(value, uri)
	end

	#POST data to query URI, simulating a user interaction
	Net::HTTP.start(params[:QUri].host, params[:QUri].port, use_ssl: false) do |http|
		req = Net::HTTP::Post.new params[:QUri]
		# Send session cookie back to Gitblit
		req['Cookie'] = HTTP::Cookie.cookie_value(cookieJar.cookies(uri))
		req.form_data = { %s{wicket:bookmarkablePage} => ':com.gitblit.wicket.pages.MyDashboardPage', id2_hf_0: "", username: user, password: pass}
		res = http.request req
		# Signal failure if we didn't get a new cookie back
		return nil if !res.get_fields('Set-Cookie') 
		# Store cookies to forward to user
		res.get_fields('Set-Cookie').each do |value|
			cookieJar.parse(value, uri)
		end
	end
	return cookieJar
end

# Sinatra routes

get '/sso/?' do
	# Show main page
	erb :index
end

post '/sso/login' do
	# Handle login
	
	# Halt on bad data
	if params.nil? || params[:user] == "" || params[:pass] == ""
		halt 418, '急須です'
	end
	# Authenticate with each service
	wikiJar = wikiAuth($wikiUri, params[:user], params[:pass], TUri: $wikiTUri)
	gitblitJar = gitblitAuth($gitblitUri, params[:user], params[:pass], QUri: $gitblitQUri)
	tepidJson = tepidAuth($tepidUri, params[:user], params[:pass])
	
	# Render failure page if any authentication did not succeed
	if wikiJar == nil || gitblitJar == nil || tepidJson == nil
		erb :failure
	else
		# Otherwise parse TEPID response for a session ID
		tepidUserId = JSON.parse(tepidJson)['_id']
		
		# Forward all cookies to the user's web browser
		wikiJar.each do |cookie|
			response.set_cookie(cookie.name, value: cookie.value, domain: '.science.mcgill.ca', path: '/' )
			#response.set_cookie(cookie.name, value: cookie.value )
		end
		gitblitJar.each do |cookie|
			response.set_cookie(cookie.name, value: cookie.value, domain: '.mcgill.ca', path: '/' )
			#response.set_cookie(cookie.name, value: cookie.value )
		end
		
		# Render the user page if user has logged in. This page saves TEPID session information to local storage
		erb :login, locals: {user: params[:user], tepidJson: tepidJson, tepidUserId: tepidUserId}
	end
end

get '/sso/logout' do
	# Handle logout

	# Halt on bad data
	cookieStr = request.env['HTTP_COOKIE']
	if cookieStr.nil?
		halt 418, '急須です'
	end
	
	# Capture the user's cookies
	cookies = HTTP::Cookie.cookie_value_to_hash(cookieStr)
	# Delete each cookie by setting it to expire at unix epoch
	cookies.each do |name, value|
		response.set_cookie(name, value: value, expires: Time.new(1970), domain: '.science.mcgill.ca', path: '/')
		response.set_cookie(name, value: value, expires: Time.new(1970), domain: '.mcgill.ca', path: '/')
	end
	erb :logout
	
end

get '*' do
	halt 418, '急須です'
end
