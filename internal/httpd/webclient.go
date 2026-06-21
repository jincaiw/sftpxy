// SPDX-License-Identifier: MIT

package httpd

import (
	"fmt"
	"html/template"
	"math"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/jincaiw/sftpxy/v2/internal/dataprovider"
	"github.com/jincaiw/sftpxy/v2/internal/util"
)

const (
	templateClientDir      = "webclient"
	templateClientBase     = "base.html"
	templateClientFiles    = "files.html"
	templateClientProfile  = "profile.html"
	templateClientMFA      = "mfa.html"
	templateClientEditFile = "editfile.html"
	templateClientShare    = "share.html"
	templateClientShares   = "shares.html"
	templateClientViewPDF  = "viewpdf.html"
	templateShareLogin     = "sharelogin.html"
	templateShareDownload  = "sharedownload.html"
	templateUploadToShare  = "shareupload.html"
)

// condResult is the result of an HTTP request precondition check.
// See https://tools.ietf.org/html/rfc7232 section 3.
type condResult int

const (
	condNone condResult = iota
	condTrue
	condFalse
)

var (
	clientTemplates = make(map[string]*template.Template)
	unixEpochTime   = time.Unix(0, 0)
)

// isZeroTime reports whether t is obviously unspecified (either zero or Unix()=0).
func isZeroTime(t time.Time) bool {
	return t.IsZero() || t.Equal(unixEpochTime)
}

type baseClientPage struct {
	commonBasePage
	Title           string
	CurrentURL      string
	FilesURL        string
	SharesURL       string
	ShareURL        string
	ProfileURL      string
	PingURL         string
	ChangePwdURL    string
	LogoutURL       string
	LoginURL        string
	EditURL         string
	MFAURL          string
	CSRFToken       string
	LoggedUser      *dataprovider.User
	IsLoggedToShare bool
	Branding        UIBranding
	Languages       []string
}

type dirMapping struct {
	DirName string
	Href    string
}

type viewPDFPage struct {
	commonBasePage
	Title     string
	URL       string
	Branding  UIBranding
	Languages []string
}

type editFilePage struct {
	baseClientPage
	CurrentDir string
	FileURL    string
	Path       string
	Name       string
	ReadOnly   bool
	Data       string
}

type filesPage struct {
	baseClientPage
	CurrentDir         string
	DirsURL            string
	FileActionsURL     string
	CheckExistURL      string
	DownloadURL        string
	ViewPDFURL         string
	FileURL            string
	TasksURL           string
	CanAddFiles        bool
	CanCreateDirs      bool
	CanRename          bool
	CanDelete          bool
	CanDownload        bool
	CanShare           bool
	CanCopy            bool
	ShareUploadBaseURL string
	Error              *util.I18nError
	Paths              []dirMapping
	QuotaUsage         *userQuotaUsage
	KeepAliveInterval  int
}

type shareLoginPage struct {
	commonBasePage
	CurrentURL    string
	Error         *util.I18nError
	CSRFToken     string
	Title         string
	Branding      UIBranding
	Languages     []string
	CheckRedirect bool
}

type shareDownloadPage struct {
	baseClientPage
	DownloadLink string
}

type shareUploadPage struct {
	baseClientPage
	Share          *dataprovider.Share
	UploadBasePath string
}

type clientMessagePage struct {
	baseClientPage
	Error   *util.I18nError
	Success string
	Text    string
}

type clientProfilePage struct {
	baseClientPage
	PublicKeys             []string
	TLSCerts               []string
	CanSubmit              bool
	AllowAPIKeyAuth        bool
	Email                  string
	AdditionalEmails       []string
	AdditionalEmailsString string
	Description            string
	Error                  *util.I18nError
}

type changeClientPasswordPage struct {
	baseClientPage
	Error          *util.I18nError
	RequiredAction *util.I18nError
}

type clientMFAPage struct {
	baseClientPage
	TOTPConfigs       []string
	TOTPConfig        dataprovider.UserTOTPConfig
	GenerateTOTPURL   string
	ValidateTOTPURL   string
	SaveTOTPURL       string
	RecCodesURL       string
	Protocols         []string
	RequiredProtocols []string
	RequiredAction    *util.I18nError
}

type clientSharesPage struct {
	baseClientPage
	BasePublicSharesURL string
	BaseURL             string
}

type clientSharePage struct {
	baseClientPage
	Share *dataprovider.Share
	Error *util.I18nError
	IsAdd bool
}

type userQuotaUsage struct {
	QuotaSize                int64
	QuotaFiles               int
	UsedQuotaSize            int64
	UsedQuotaFiles           int
	UploadDataTransfer       int64
	DownloadDataTransfer     int64
	TotalDataTransfer        int64
	UsedUploadDataTransfer   int64
	UsedDownloadDataTransfer int64
}

func (u *userQuotaUsage) HasQuotaInfo() bool {
	if dataprovider.GetQuotaTracking() == 0 {
		return false
	}
	if u.HasDiskQuota() {
		return true
	}
	return u.HasTranferQuota()
}

func (u *userQuotaUsage) HasDiskQuota() bool {
	if u.QuotaSize > 0 || u.UsedQuotaSize > 0 {
		return true
	}
	return u.QuotaFiles > 0 || u.UsedQuotaFiles > 0
}

func (u *userQuotaUsage) HasTranferQuota() bool {
	if u.TotalDataTransfer > 0 || u.UploadDataTransfer > 0 || u.DownloadDataTransfer > 0 {
		return true
	}
	return u.UsedDownloadDataTransfer > 0 || u.UsedUploadDataTransfer > 0
}

func (u *userQuotaUsage) GetQuotaSize() string {
	if u.QuotaSize > 0 {
		return fmt.Sprintf("%s/%s", util.ByteCountIEC(u.UsedQuotaSize), util.ByteCountIEC(u.QuotaSize))
	}
	if u.UsedQuotaSize > 0 {
		return util.ByteCountIEC(u.UsedQuotaSize)
	}
	return ""
}

func (u *userQuotaUsage) GetQuotaFiles() string {
	if u.QuotaFiles > 0 {
		return fmt.Sprintf("%d/%d", u.UsedQuotaFiles, u.QuotaFiles)
	}
	if u.UsedQuotaFiles > 0 {
		return strconv.FormatInt(int64(u.UsedQuotaFiles), 10)
	}
	return ""
}

func (u *userQuotaUsage) GetQuotaSizePercentage() int {
	if u.QuotaSize > 0 {
		return int(math.Round(100 * float64(u.UsedQuotaSize) / float64(u.QuotaSize)))
	}
	return 0
}

func (u *userQuotaUsage) GetQuotaFilesPercentage() int {
	if u.QuotaFiles > 0 {
		return int(math.Round(100 * float64(u.UsedQuotaFiles) / float64(u.QuotaFiles)))
	}
	return 0
}

func (u *userQuotaUsage) IsQuotaSizeLow() bool {
	return u.GetQuotaSizePercentage() > 85
}

func (u *userQuotaUsage) IsQuotaFilesLow() bool {
	return u.GetQuotaFilesPercentage() > 85
}

func (u *userQuotaUsage) IsDiskQuotaLow() bool {
	return u.IsQuotaSizeLow() || u.IsQuotaFilesLow()
}

func (u *userQuotaUsage) GetTotalTransferQuota() string {
	total := u.UsedUploadDataTransfer + u.UsedDownloadDataTransfer
	if u.TotalDataTransfer > 0 {
		return fmt.Sprintf("%s/%s", util.ByteCountIEC(total), util.ByteCountIEC(u.TotalDataTransfer*1048576))
	}
	if total > 0 {
		return util.ByteCountIEC(total)
	}
	return ""
}

func (u *userQuotaUsage) GetUploadTransferQuota() string {
	if u.UploadDataTransfer > 0 {
		return fmt.Sprintf("%s/%s", util.ByteCountIEC(u.UsedUploadDataTransfer),
			util.ByteCountIEC(u.UploadDataTransfer*1048576))
	}
	if u.UsedUploadDataTransfer > 0 {
		return util.ByteCountIEC(u.UsedUploadDataTransfer)
	}
	return ""
}

func (u *userQuotaUsage) GetDownloadTransferQuota() string {
	if u.DownloadDataTransfer > 0 {
		return fmt.Sprintf("%s/%s", util.ByteCountIEC(u.UsedDownloadDataTransfer),
			util.ByteCountIEC(u.DownloadDataTransfer*1048576))
	}
	if u.UsedDownloadDataTransfer > 0 {
		return util.ByteCountIEC(u.UsedDownloadDataTransfer)
	}
	return ""
}

func (u *userQuotaUsage) GetTotalTransferQuotaPercentage() int {
	if u.TotalDataTransfer > 0 {
		return int(math.Round(100 * float64(u.UsedDownloadDataTransfer+u.UsedUploadDataTransfer) / float64(u.TotalDataTransfer*1048576)))
	}
	return 0
}

func (u *userQuotaUsage) GetUploadTransferQuotaPercentage() int {
	if u.UploadDataTransfer > 0 {
		return int(math.Round(100 * float64(u.UsedUploadDataTransfer) / float64(u.UploadDataTransfer*1048576)))
	}
	return 0
}

func (u *userQuotaUsage) GetDownloadTransferQuotaPercentage() int {
	if u.DownloadDataTransfer > 0 {
		return int(math.Round(100 * float64(u.UsedDownloadDataTransfer) / float64(u.DownloadDataTransfer*1048576)))
	}
	return 0
}

func (u *userQuotaUsage) IsTotalTransferQuotaLow() bool {
	if u.TotalDataTransfer > 0 {
		return u.GetTotalTransferQuotaPercentage() > 85
	}
	return false
}

func (u *userQuotaUsage) IsUploadTransferQuotaLow() bool {
	if u.UploadDataTransfer > 0 {
		return u.GetUploadTransferQuotaPercentage() > 85
	}
	return false
}

func (u *userQuotaUsage) IsDownloadTransferQuotaLow() bool {
	if u.DownloadDataTransfer > 0 {
		return u.GetDownloadTransferQuotaPercentage() > 85
	}
	return false
}

func (u *userQuotaUsage) IsTransferQuotaLow() bool {
	return u.IsTotalTransferQuotaLow() || u.IsUploadTransferQuotaLow() || u.IsDownloadTransferQuotaLow()
}

func (u *userQuotaUsage) IsQuotaLow() bool {
	return u.IsDiskQuotaLow() || u.IsTransferQuotaLow()
}

func newUserQuotaUsage(u *dataprovider.User) *userQuotaUsage {
	return &userQuotaUsage{
		QuotaSize:                u.QuotaSize,
		QuotaFiles:               u.QuotaFiles,
		UsedQuotaSize:            u.UsedQuotaSize,
		UsedQuotaFiles:           u.UsedQuotaFiles,
		TotalDataTransfer:        u.TotalDataTransfer,
		UploadDataTransfer:       u.UploadDataTransfer,
		DownloadDataTransfer:     u.DownloadDataTransfer,
		UsedUploadDataTransfer:   u.UsedUploadDataTransfer,
		UsedDownloadDataTransfer: u.UsedDownloadDataTransfer,
	}
}

func getFileObjectURL(baseDir, name, baseWebPath string) string {
	return fmt.Sprintf("%v?path=%v&_=%v", baseWebPath, url.QueryEscape(path.Join(baseDir, name)), time.Now().UTC().Unix())
}

func getFileObjectModTime(t time.Time) int64 {
	if isZeroTime(t) {
		return 0
	}
	return t.UnixMilli()
}

func getDirMapping(dirName, baseWebPath string) []dirMapping {
	paths := []dirMapping{}
	if dirName != "/" {
		paths = append(paths, dirMapping{
			DirName: path.Base(dirName),
			Href:    getFileObjectURL("/", dirName, baseWebPath),
		})
		for {
			dirName = path.Dir(dirName)
			if dirName == "/" || dirName == "." {
				break
			}
			paths = append([]dirMapping{{
				DirName: path.Base(dirName),
				Href:    getFileObjectURL("/", dirName, baseWebPath)},
			}, paths...)
		}
	}
	return paths
}

func checkShareRedirectURL(next, base string) (bool, string) {
	if !strings.HasPrefix(next, base) {
		return false, ""
	}
	if next == base {
		return true, path.Join(next, "download")
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return false, ""
	}
	nextURL, err := url.Parse(next)
	if err != nil {
		return false, ""
	}
	if nextURL.Path == baseURL.Path {
		redirectURL := nextURL.JoinPath("download")
		return true, redirectURL.String()
	}
	return true, next
}

type filesToCheck struct {
	Files []string `json:"files"`
}
