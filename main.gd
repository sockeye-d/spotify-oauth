extends Control

const HEADERS := "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\nContent-Length: %s\n\n"
const TEMPLATE := """
<html>
<style>
	@import url('https://fonts.googleapis.com/css2?family=Atkinson+Hyperlegible:ital,wght@0,400;0,700;1,400;1,700&display=swap');

	:root {
		font-family: "Atkinson Hyperlegible";
	}

	body {
		margin: 0px;
		background: linear-gradient(45deg, #09111a, #0e1620);
	}

	.centered {
		display: flex;
		width: 100vw;
		height: 100vh;
		max-width: 100%%;
		max-height: 100%%;
		justify-content: center;
		align-items: center;
	}

	.card {
		background-color: #0e1e2c;
		padding: 32px;
		border-radius: 64px;
		box-shadow: 0px 32px 32px rgba(0, 0, 0, 0.356);
	}

	h1 {
		color: rgb(216, 224, 230);
		margin: 0px;
		font-size: 3em;
	}

	* {
		color: rgba(216, 224, 230, 0.753);
		margin: 0px;
		font-size: 24px;
	}
</style>
<div class="centered">
	<div class="card">
		<h1>
			%s
		</h1>
		This window can be closed now
	</div>
</div>

</html>
"""

const SUCCESS_RESPONSE := TEMPLATE % "Authentication succeeded"
const FAILED_RESPONSE := TEMPLATE % "Authentication failed for reason '{0}'"


var client_info: OAuthSecrets


var server := OAuthServer.new()
var secret: String
var auth_key: String
var token: String


@onready var http_request: HTTPRequest = %HTTPRequest


func _ready() -> void:
	client_info = load("res://client.tres")
	assert(client_info != null, "Must have client info")
	
	server.listen(client_info.localhost_port)
	server.oauth_completed.connect(func(params: Dictionary[String, String]):
		print("Got authorization key")
		if "error" in params:
			server.send_data(HEADERS, FAILED_RESPONSE.format([params.error]))
			return
		else:
			server.send_data(HEADERS, SUCCESS_RESPONSE)
		#server.stop()
		#return
		if params.state == secret:
			print("secret does match")
		else:
			print("secret doesn't match")
		auth_key = params.code
		print("Getting token")
		http_request.request("https://accounts.spotify.com/api/token", [
			"content-type: application/x-www-form-urlencoded",
			"Authorization: Basic " + Marshalls.utf8_to_base64(client_info.client_id + ":" + client_info.client_secret),
		], HTTPClient.METHOD_POST, convert_url_params({
			"code": auth_key,
			"redirect_uri": "http://localhost:7158",
			"grant_type": "authorization_code"
		}))
	)
	authenticate()


func _exit_tree() -> void:
	server.stop()


func _process(delta: float) -> void:
	if not server.is_finished():
		server.poll()


func authenticate() -> void:
	secret = Crypto.new().generate_random_bytes(60).hex_encode().substr(0, 16)
	OS.shell_open("https://accounts.spotify.com/authorize?" + convert_url_params({
		"response_type": 'code',
		"client_id": client_info.client_id,
		
		# https://developer.spotify.com/documentation/web-api/concepts/scopes#streaming
		"scope": "user-read-playback-state user-modify-playback-state",
		"redirect_uri": "http://localhost:7158",
		"state": secret,
	}))


func convert_url_params(params: Dictionary[String, String]) -> String:
	return "&".join(PackedStringArray(params.keys().map(func(key: String): return key + "=" + params[key])))


class OAuthServer extends TCPServer:
	signal oauth_completed(headers: Dictionary[String, String])
	
	var content: PackedByteArray
	var peer: StreamPeerTCP
	var finished: bool = false
	
	func start(port: int) -> Error:
		finished = false
		return listen(port)
	
	func poll() -> void:
		if finished:
			push_error("Already finished!")
			return
		if is_connection_available():
			peer = take_connection()
		if peer:
			peer.poll()
			if content and peer.get_available_bytes() == 0:
				finished = true
				oauth_completed.emit(parse_headers())
			if peer.get_available_bytes():
				# who needs error handling when you can have error unhandling
				content.append_array(peer.get_data(peer.get_available_bytes())[1])
	
	func is_finished() -> bool:
		return finished
	
	func parse_headers(headers: String = content.get_string_from_ascii()) -> Dictionary[String, String]:
		var start_index := headers.find("/?")
		if start_index == -1:
			return { }
		start_index += 2
		var end_index := headers.find(" ", start_index)
		if end_index == -1:
			return { }
		var params := headers.substr(start_index, end_index - start_index)
		var d: Dictionary[String, String]
		var params_arr := params.split("&")
		for param in params_arr:
			var param_split := param.split("=")
			d[param_split[0]] = param_split[1]
		return d
	
	## Sends data to the connected peer if there is one. [param headers] should contain one
	## replacement ([code]%s[/code]) which will be replaced by the length of [param content]
	func send_data(headers: String, content: String) -> void:
		if not peer:
			return
		peer.put_data((headers % content.length()).to_ascii_buffer())
		peer.put_data(content.to_utf8_buffer())


func _on_button_pressed() -> void:
	print(error_string(http_request.request("https://api.spotify.com/v1/me/player/pause", [
		"Authorization: Bearer " + token,
	], HTTPClient.METHOD_PUT, " ")))


func _on_http_request_request_completed(result: int, response_code: int, headers: PackedStringArray, body: PackedByteArray) -> void:
	print(result)
	print(response_code)
	print(headers)
	var body_str := body.get_string_from_utf8()
	print(body_str)
	var data = JSON.parse_string(body_str)
	if data and "access_token" in data:
		token = data.access_token
