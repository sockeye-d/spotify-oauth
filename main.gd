extends Control


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
		server.stop()
		if params.state == secret:
			print("secret does match")
		else:
			print("secret doesn't match")
		auth_key = params.code
		print("Getting token")
		print(error_string(http_request.request("https://accounts.spotify.com/api/token", [
			"content-type: application/x-www-form-urlencoded",
			"Authorization: Basic " + Marshalls.utf8_to_base64(client_info.client_id + ":" + client_info.client_secret),
		], HTTPClient.METHOD_POST, convert_url_params({
			"code": auth_key,
			"redirect_uri": "http://localhost:7158",
			"grant_type": "authorization_code"
		}))))
	)
	authenticate()


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
				content.append_array(peer.get_data(peer.get_available_bytes())[1])
	
	func is_finished() -> bool:
		return finished
	
	# just returns the code since that's all we need
	func parse_headers(headers: String = content.get_string_from_ascii()) -> Dictionary[String, String]:
		var start_index := headers.find("/?") + 2
		var end_index := headers.find(" ", start_index)
		var params := headers.substr(start_index, end_index - start_index)
		var d: Dictionary[String, String]
		var params_arr := params.split("&")
		for param in params_arr:
			var param_split := param.split("=")
			d[param_split[0]] = param_split[1]
		return d


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
