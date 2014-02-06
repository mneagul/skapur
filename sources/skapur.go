

package main


import "crypto/hmac"
import "crypto/sha256"
import "encoding/hex"
import "flag"
import "io"
import "log"
import "net/http"
import "os"
import "path"
import "regexp"


var _address string = "127.0.0.1:8080"
var _secret string = ""
var _store string = "/tmp/skapur"

var _getPath = regexp.MustCompile ("^/skapur/v1/([a-zA-Z0-9][a-zA-Z0-9_.-]+[a-zA-Z0-9])$")
var _putPath = regexp.MustCompile ("^/skapur/v1/([a-zA-Z0-9][a-zA-Z0-9_.-]+[a-zA-Z0-9])(?::((?:[0-9a-f][0-9a-f])+))?$")


func handle (_response http.ResponseWriter, _request *http.Request) () {
	
	_method := _request.Method
	_path := _request.URL.Path
	_requester := _request.RemoteAddr
	
	log.Printf ("handling request `%s` `%s` from `%s`...", _method, _path, _requester)
	
	switch {
		
		case _method == "GET" :
			if _match := _getPath.FindAllStringSubmatch (_path, 1); _match != nil {
				handleGet (_match[0][1], _response, _request)
			} else {
				log.Printf ("invalid path `%s`; failing!\n", _path)
				http.Error (_response, "bad-request", http.StatusBadRequest)
			}
		
		case _method == "PUT" :
			if _match := _putPath.FindAllStringSubmatch (_path, 1); _match != nil {
				handlePut (_match[0][1], _match[0][2], _response, _request)
			} else {
				log.Printf ("invalid path `%s`; failing!\n", _path)
				http.Error (_response, "bad-request", http.StatusBadRequest)
			}
		
		default :
			log.Printf ("invalid method `%s`; failing!\n", _method)
			http.Error (_response, "not-implemented", http.StatusNotImplemented)
	}
	
}


func handleGet (_path string, _response http.ResponseWriter, _request *http.Request) {
	
	log.Printf ("fetching file `%s`...\n", _path)
	
	_path = path.Join (_store, _path)
	
	http.ServeFile (_response, _request, _path)
}


func handlePut (_path string, _signature string, _response http.ResponseWriter, _request *http.Request) {
	
	log.Printf ("storing file `%s` with signature `%s`...\n", _path, _signature)
	
	if _secret != "" {
		
		_hasher := hmac.New (sha256.New, []byte (_secret))
		_hasher.Write ([]byte (_path))
		_expected := hex.EncodeToString (_hasher.Sum (nil))
		log.Printf ("expecting signature `%s`...\n", _expected)
		
		if _expected != _signature {
			log.Printf ("invalid signature `%s`; failing!\n", _signature)
			http.Error (_response, "unauthorized", http.StatusUnauthorized)
			return
		}
		
	} else if _signature != "" {
		
		log.Printf ("invalid signature `%s`; failing!\n", _signature)
		http.Error (_response, "unauthorized", http.StatusUnauthorized)
		return
	}
	
	_path = path.Join (_store, _path)
	
	_stream, _error := os.OpenFile (_path, os.O_CREATE | os.O_EXCL | os.O_WRONLY, 0600)
	if _error != nil {
		
		log.Printf ("error encountered while creating the file `%s`: `%s`; failing!\n", _path, _error)
		http.Error (_response, "failed-exists", http.StatusInternalServerError)
		return
	}
	
	_size, _error := io.Copy (_stream, _request.Body)
	
	if _error != nil {
		
		os.Remove (_path)
		log.Printf ("error encountered while writing the file `%s`: `%s`; failing!\n", _path, _error)
		http.Error (_response, "failed-error", http.StatusInternalServerError)
		return
	}
	
	log.Printf ("succeeded in writing the file `%s` of `%d` bytes.", _path, _size)
	
	_response.WriteHeader (http.StatusCreated)
}


func main () () {
	
	flag.StringVar (&_address, "address", _address, "listening address <ip>:<port>")
	flag.StringVar (&_store, "store", _store, "store path")
	flag.StringVar (&_secret, "secret", _secret, "secret key for HMAC-SHA256")
	flag.Parse ()
	if flag.NArg () != 0 {
		log.Fatalf ("unexpected extra arguments")
		os.Exit (1)
	}
	
	log.Printf ("listening on `%s` with secret `%s`...", _address, _secret)
	if _error := http.ListenAndServe (_address, http.HandlerFunc (handle)); _error != nil {
		log.Fatalf ("error encountered while listening; aborting! %v\n", _error)
		os.Exit (1)
	}
}
