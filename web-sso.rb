require 'net/http'
require 'http-cookie'
require 'nokogiri'
require 'json'
require 'sinatra'

# Store uris
$wikiUri = URI("https://tepid.science.mcgill.ca/wiki/index.php/Special:UserLogin")
$wikiTUri = URI("https://tepid.science.mcgill.ca/wiki/api.php?action=query&format=json&meta=tokens&type=login")
$tepidUri = URI("http://tepid.science.mcgill.ca/tepid/sessions/")
$gitblitUri = URI("http://git.sus.mcgill.ca:8080/gitblit/")
$gitblitQUri = URI("http://git.sus.mcgill.ca:8080/gitblit/?wicket:interface=:1:userPanel:loginForm::IFormSubmitListener::")


def wikiAuth(uri, user, pass, params=nil)
	# Authenticate with Mediawiki
	cookieJar = HTTP::CookieJar.new
	res = Net::HTTP.get_response(uri)
	res.get_fields('Set-Cookie').each do |value|
		cookieJar.parse(value,uri)
	end

	page = Nokogiri::HTML(res.body)
	loginToken = page.css('input[name=wpLoginToken]').first['value']

	Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
		req = Net::HTTP::Post.new uri
		req.form_data = { wpName: user, wpPassword: pass, wploginattempt: 'Log+in', wpEditToken: '+\\', title: 'Special:userLogin', authAction: 'login', force: '', wpLoginToken: loginToken } 
		req['Cookie'] = HTTP::Cookie.cookie_value(cookieJar.cookies(uri))
		res = http.request req
		puts res.body
		return nil if res.code.to_i == 200
		res.get_fields('Set-Cookie').each do |value|
			cookieJar.parse(value, uri)
		end
	end
	return cookieJar
end

def tepidAuth(uri, user, pass)
	resJson = nil
	Net::HTTP.start(uri.host, 8443, use_ssl: true) do |http|
		req = Net::HTTP::Post.new(uri, "Content-Type" => 'application/json;charset=utf-8', "Accept" => 'application/json, text/plain, */*')
		req.body = JSON.generate({username: user, password: pass, persistent: false})
		res = http.request req
		return nil if res.code.to_i != 200
		resJson = res.body
	end
	return resJson
end

def gitblitAuth(uri, user, pass, params = nil)
	cookieJar = HTTP::CookieJar.new
	res = Net::HTTP.get_response(uri)
	res.get_fields('Set-Cookie').each do |value|
		cookieJar.parse(value, uri)
	end
	Net::HTTP.start(params[:QUri].host, params[:QUri].port, use_ssl: false) do |http|
		req = Net::HTTP::Post.new params[:QUri]
		req['Cookie'] = HTTP::Cookie.cookie_value(cookieJar.cookies(uri))
		req.form_data = { %s{wicket:bookmarkablePage} => ':com.gitblit.wicket.pages.MyDashboardPage', id2_hf_0: "", username: user, password: pass}
		res = http.request req
		return nil if !res.get_fields('Set-Cookie') 
		res.get_fields('Set-Cookie').each do |value|
			cookieJar.parse(value, uri)
		end
	end
	return cookieJar
end

get '/' do
	erb :index
end

post '/login' do
	if params.nil? || params[:user] == "" || params[:pass] == ""
		halt 418, '急須です'
	end
	wikiJar = wikiAuth($wikiUri, params[:user], params[:pass], TUri: $wikiTUri)
	gitblitJar = gitblitAuth($gitblitUri, params[:user], params[:pass], QUri: $gitblitQUri)
	tepidJson = tepidAuth($tepidUri, params[:user], params[:pass])

	if wikiJar == nil || gitblitJar == nil || tepidJson == nil
		erb :failure
	else
		tepidUserId = JSON.parse(tepidJson)['_id']
		
		wikiJar.each do |cookie|
			#response.set_cookie(cookie.name, value: cookie.value, domain: '.science.mcgill.ca' )
			response.set_cookie(cookie.name, value: cookie.value )
		end
		gitblitJar.each do |cookie|
			#response.set_cookie(cookie.name, value: cookie.value, domain: '.mcgill.ca' )
			response.set_cookie(cookie.name, value: cookie.value )
		end

		rstr = HTTP::Cookie.cookie_value(wikiJar.cookies($wikiUri))
		erb :login, locals: {user: params[:user], tepidJson: tepidJson, tepidUserId: tepidUserId}
	end
end

get '/logout' do
	cookieStr = request.env['HTTP_COOKIE']
	if cookieStr.nil?
		halt 418, '急須です'
	end
	
	cookies = HTTP::Cookie.cookie_value_to_hash(cookieStr)
	cookies.each do |name, value|
		response.set_cookie(name, value: value, expires: Time.new(1970))
	end
	erb :logout
	
end

