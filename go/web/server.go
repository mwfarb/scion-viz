// go run sub/scion-viz/go/web/server.go -a 0.0.0.0 -p 8000 -r .

package main

import (
    "bytes"
    "encoding/base64"
    "flag"
    "fmt"
    "golang.org/x/image/font"
    "golang.org/x/image/font/basicfont"
    "golang.org/x/image/math/fixed"
    "html/template"
    "image"
    "image/color"
    "image/draw"
    "image/gif"
    "image/jpeg"
    "image/png"
    "io"
    "io/ioutil"
    "log"
    "math/rand"
    "net"
    "net/http"
    "os"
    "os/exec"
    "path"
    "regexp"
    "runtime"
    "strconv"
    "time"
)

var addr = flag.String("a", "127.0.0.1", "server host address")
var port = flag.Int("p", 8000, "server port number")
var root = flag.String("r", ".", "file system path to browse from")
var cmdBufLen = 1024

var imgTemplate = `<!doctype html><html lang="en"><head></head>
<body><img src="data:image/jpg;base64,{{.Image}}"></body>`

var regexImg = `([^\s]+(\.(?i)(jp?g|png|gif))$)`

func main() {
    flag.Parse()

    http.HandleFunc("/", mainHandler)
    http.Handle("/files/", http.StripPrefix("/files/", http.FileServer(http.Dir(*root))))
    http.HandleFunc("/img", genImageHandler)
    http.HandleFunc("/launch", launchHandler)
    http.HandleFunc("/imglast", findImageHandler)
    http.HandleFunc("/txtlast", findImageInfoHandler)

    log.Printf("Browser access at http://%s:%d.\n", *addr, *port)
    log.Printf("File server root: %s\n", *root)
    log.Printf("Listening on %s:%d...\n", *addr, *port)
    log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", *addr, *port), nil))
}

// Handles loading index.html for user at root.
func mainHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/html")
    w.WriteHeader(http.StatusOK)

    _, rootfile, _, _ := runtime.Caller(0)
    filepath := path.Join(path.Dir(rootfile), "index.html")
    data, err := ioutil.ReadFile(filepath)
    if err != nil {
        log.Fatal("ioutil.ReadFile() error: " + err.Error())
    }
    w.Header().Set("Content-Length", fmt.Sprint(len(data)))
    fmt.Fprint(w, string(data))
}

// Handles parsing SCION addresses to execute client app and write results.
func launchHandler(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    iaSer := r.PostFormValue("ia_ser")
    iaCli := r.PostFormValue("ia_cli")
    addrSer := r.PostFormValue("addr_ser")
    addrCli := r.PostFormValue("addr_cli")
    portSer := r.PostFormValue("port_ser")
    portCli := r.PostFormValue("port_cli")
    addlOpt := r.PostFormValue("addl_opt")
    appSel := r.PostFormValue("apps")

    // execute scion go client app with client/server commands
    _, rootfile, _, _ := runtime.Caller(0)
    gopath := os.Getenv("GOPATH")
    slroot := "src/github.com/perrig/scionlab"
    var filepath string
    switch appSel {
    case "sensorapp":
        filepath = path.Join(gopath, slroot, "sensorapp/sensorfetcher/sensorfetcher.go")
    case "camerapp":
        filepath = path.Join(gopath, slroot, "camerapp/imagefetcher/imagefetcher.go")
    case "bwtester":
        filepath = path.Join(gopath, slroot, "bwtester/bwtestclient/bwtestclient.go")
    case "demotime":
        filepath = path.Join(path.Dir(rootfile), "../demo/scion-pydemo-client.go")
    case "demoimage":
        filepath = path.Join(path.Dir(rootfile), "../demo/scion-imgdemo-client.go")
    default:
        fmt.Fprintf(w, "Unknown SCION client app. Is one selected?")
        return
    }

    optClient := fmt.Sprintf("-c=%s", fmt.Sprintf("%s,[%s]:%s", iaCli, addrCli, portCli))
    optServer := fmt.Sprintf("-s=%s", fmt.Sprintf("%s,[%s]:%s", iaSer, addrSer, portSer))
    log.Printf("Executing: go run %s %s %s %s\n", filepath, optClient, optServer, addlOpt)
    cmd := exec.Command("go", "run", filepath, optServer, optClient, addlOpt)

    // pipe command results to page
    pipeReader, pipeWriter := io.Pipe()
    cmd.Stdout = pipeWriter
    cmd.Stderr = pipeWriter
    go writeCmdOutput(w, pipeReader)
    cmd.Run()
    pipeWriter.Close()
}

// Handles piping command line output to http response writer.
func writeCmdOutput(w http.ResponseWriter, pr *io.PipeReader) {
    buf := make([]byte, cmdBufLen)
    for {
        n, err := pr.Read(buf)
        if err != nil {
            pr.Close()
            break
        }
        output := buf[0:n]
        w.Write(output)
        if f, ok := w.(http.Flusher); ok {
            f.Flush()
        }
        for i := 0; i < n; i++ {
            buf[i] = 0
        }
    }
}

// Handles generation of machine date, name, interfaces in an image served
// to the page.
func genImageHandler(w http.ResponseWriter, r *http.Request) {
    // generate random light-colored image
    m := image.NewRGBA(image.Rect(0, 0, 250, 250))
    rand.Seed(time.Now().UnixNano())
    rr := uint8(rand.Intn(127) + 127)
    rg := uint8(rand.Intn(127) + 127)
    rb := uint8(rand.Intn(127) + 127)
    color := color.RGBA{rr, rg, rb, 255}
    draw.Draw(m, m.Bounds(), &image.Uniform{color}, image.ZP, draw.Src)

    // add time to img
    x, y := 5, 100
    addImgLabel(m, x, y, time.Now().Format(time.RFC850))

    // add hostname to img
    name, err := os.Hostname()
    if err != nil {
        log.Println("os.Hostname() error: " + err.Error())
    }
    y += 20
    addImgLabel(m, x, y, name)

    // add address to img
    addrs, err := net.InterfaceAddrs()
    if err != nil {
        log.Println("net.InterfaceAddrs() error: " + err.Error())
    }
    for _, a := range addrs {
        if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
            if ipnet.IP.To4() != nil {
                y += 20
                addrStr := fmt.Sprintf("%s (%s)", ipnet.IP.String(), a.Network())
                addImgLabel(m, x, y, addrStr)
            }
        }
    }

    var img image.Image = m
    writeJpegTemplate(w, &img)
}

// Configures font to render label at x, y on the img.
func addImgLabel(img *image.RGBA, x, y int, label string) {
    col := color.RGBA{0, 0, 0, 255}
    point := fixed.Point26_6{fixed.Int26_6(x * 64), fixed.Int26_6(y * 64)}
    d := &font.Drawer{
        Dst:  img,
        Src:  image.NewUniform(col),
        Face: basicfont.Face7x13,
        Dot:  point,
    }
    d.DrawString(label)
}

// Handles writing jpeg image to http response writer by content-type.
func writeJpegContentType(w http.ResponseWriter, img *image.Image) {
    buf := new(bytes.Buffer)
    err := jpeg.Encode(buf, *img, nil)
    if err != nil {
        log.Println("jpeg.Encode() error: " + err.Error())
    }
    w.Header().Set("Content-Type", "image/jpeg")
    w.Header().Set("Content-Length", strconv.Itoa(len(buf.Bytes())))
    _, werr := w.Write(buf.Bytes())
    if werr != nil {
        log.Println("w.Write() image error: " + werr.Error())
    }
}

// Handles writing jpeg image to http response writer by image template.
func writeJpegTemplate(w http.ResponseWriter, img *image.Image) {
    buf := new(bytes.Buffer)
    err := jpeg.Encode(buf, *img, nil)
    if err != nil {
        log.Println("jpeg.Encode() error: " + err.Error())
    }
    str := base64.StdEncoding.EncodeToString(buf.Bytes())
    tmpl, err := template.New("image").Parse(imgTemplate)
    if err != nil {
        log.Println("tmpl.Parse() image error: " + err.Error())
    } else {
        data := map[string]interface{}{"Image": str}
        err := tmpl.Execute(w, data)
        if err != nil {
            log.Println("tmpl.Execute() image error: " + err.Error())
        }
    }
}

// Helper method to find most recently modified regex extRegEx filename in dir.
func findNewestImage(dir, extRegEx string) (imgFilename string, imgTimestamp int64) {
    files, _ := ioutil.ReadDir(dir)
    for _, f := range files {
        fi, err := os.Stat(dir + f.Name())
        if err != nil {
            log.Println("os.Stat() error: " + err.Error())
        }
        matched, err := regexp.MatchString(extRegEx, f.Name())
        if matched {
            modTime := fi.ModTime().Unix()
            if modTime > imgTimestamp {
                imgTimestamp = modTime
                imgFilename = f.Name()
            }
        }
    }
    return
}

// Handles locating most recent image and writing text info data about it.
func findImageInfoHandler(w http.ResponseWriter, r *http.Request) {
    imgFilename, imgTimestamp := findNewestImage(*root, regexImg)
    if imgFilename == "" {
        return
    }
    t := time.Unix(imgTimestamp, 0)
    d := time.Since(t)
    fileText := imgFilename + " modified " + d.Truncate(time.Minute).String() + " ago."
    fmt.Fprintf(w, fileText)
}

// Handles locating most recent image formatting it for graphic display in response.
func findImageHandler(w http.ResponseWriter, r *http.Request) {
    imgFilename, _ := findNewestImage(*root, regexImg)
    if imgFilename == "" {
        return
    }
    log.Println("Found image file: " + imgFilename)
    imgFile, err := os.Open(*root + imgFilename)
    if err != nil {
        log.Println("os.Open() error: " + err.Error())
    }
    defer imgFile.Close()
    _, imageType, err := image.Decode(imgFile)
    if err != nil {
        log.Println("image.Decode() error: " + err.Error())
    }
    log.Println("Found image type: " + imageType)
    // reset file pointer to beginning
    imgFile.Seek(0, 0)
    var rawImage image.Image
    switch imageType {
    case "gif":
        rawImage, err = gif.Decode(imgFile)
    case "png":
        rawImage, err = png.Decode(imgFile)
    case "jpeg":
        rawImage, err = jpeg.Decode(imgFile)
    default:
        panic("Unhandled image type!")
    }
    if err != nil {
        log.Println("png.Decode() error: " + err.Error())
    }
    writeJpegTemplate(w, &rawImage)
}
