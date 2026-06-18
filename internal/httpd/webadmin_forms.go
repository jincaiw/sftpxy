// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package httpd

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

func getUserFromPostFields(r *http.Request) (dataprovider.User, error) {
	user := dataprovider.User{}
	err := r.ParseMultipartForm(maxRequestSize)
	if err != nil {
		return user, util.NewI18nError(err, util.I18nErrorInvalidForm)
	}
	defer r.MultipartForm.RemoveAll() //nolint:errcheck

	updateRepeaterFormFields(r)

	uid, err := strconv.Atoi(r.Form.Get("uid"))
	if err != nil {
		return user, fmt.Errorf("invalid uid: %w", err)
	}
	gid, err := strconv.Atoi(r.Form.Get("gid"))
	if err != nil {
		return user, fmt.Errorf("invalid uid: %w", err)
	}
	maxSessions, err := strconv.Atoi(r.Form.Get("max_sessions"))
	if err != nil {
		return user, fmt.Errorf("invalid max sessions: %w", err)
	}
	quotaSize, quotaFiles, err := getQuotaLimits(r)
	if err != nil {
		return user, err
	}
	bandwidthUL, err := strconv.ParseInt(r.Form.Get("upload_bandwidth"), 10, 64)
	if err != nil {
		return user, fmt.Errorf("invalid upload bandwidth: %w", err)
	}
	bandwidthDL, err := strconv.ParseInt(r.Form.Get("download_bandwidth"), 10, 64)
	if err != nil {
		return user, fmt.Errorf("invalid download bandwidth: %w", err)
	}
	dataTransferUL, dataTransferDL, dataTransferTotal, err := getTransferLimits(r)
	if err != nil {
		return user, err
	}
	status, err := strconv.Atoi(r.Form.Get("status"))
	if err != nil {
		return user, fmt.Errorf("invalid status: %w", err)
	}
	expirationDateMillis := int64(0)
	expirationDateString := r.Form.Get("expiration_date")
	if strings.TrimSpace(expirationDateString) != "" {
		expirationDate, err := time.Parse(webDateTimeFormat, expirationDateString)
		if err != nil {
			return user, err
		}
		expirationDateMillis = util.GetTimeAsMsSinceEpoch(expirationDate)
	}
	fsConfig, err := getFsConfigFromPostFields(r)
	if err != nil {
		return user, err
	}
	filters, err := getFiltersFromUserPostFields(r)
	if err != nil {
		return user, err
	}
	filters.TLSCerts = r.Form["tls_certs"]
	user = dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username:             strings.TrimSpace(r.Form.Get("username")),
			Email:                strings.TrimSpace(r.Form.Get("email")),
			Password:             strings.TrimSpace(r.Form.Get("password")),
			PublicKeys:           r.Form["public_keys"],
			HomeDir:              strings.TrimSpace(r.Form.Get("home_dir")),
			UID:                  uid,
			GID:                  gid,
			Permissions:          getUserPermissionsFromPostFields(r),
			MaxSessions:          maxSessions,
			QuotaSize:            quotaSize,
			QuotaFiles:           quotaFiles,
			UploadBandwidth:      bandwidthUL,
			DownloadBandwidth:    bandwidthDL,
			UploadDataTransfer:   dataTransferUL,
			DownloadDataTransfer: dataTransferDL,
			TotalDataTransfer:    dataTransferTotal,
			Status:               status,
			ExpirationDate:       expirationDateMillis,
			AdditionalInfo:       r.Form.Get("additional_info"),
			Description:          r.Form.Get("description"),
			Role:                 strings.TrimSpace(r.Form.Get("role")),
		},
		Filters: dataprovider.UserFilters{
			BaseUserFilters:       filters,
			RequirePasswordChange: r.Form.Get("require_password_change") != "",
			AdditionalEmails:      r.Form["additional_emails"],
		},
		VirtualFolders: getVirtualFoldersFromPostFields(r),
		FsConfig:       fsConfig,
		Groups:         getGroupsFromUserPostFields(r),
	}
	return user, nil
}

func getGroupFromPostFields(r *http.Request) (dataprovider.Group, error) {
	group := dataprovider.Group{}
	err := r.ParseMultipartForm(maxRequestSize)
	if err != nil {
		return group, util.NewI18nError(err, util.I18nErrorInvalidForm)
	}
	defer r.MultipartForm.RemoveAll() //nolint:errcheck

	updateRepeaterFormFields(r)

	maxSessions, err := strconv.Atoi(r.Form.Get("max_sessions"))
	if err != nil {
		return group, fmt.Errorf("invalid max sessions: %w", err)
	}
	quotaSize, quotaFiles, err := getQuotaLimits(r)
	if err != nil {
		return group, err
	}
	bandwidthUL, err := strconv.ParseInt(r.Form.Get("upload_bandwidth"), 10, 64)
	if err != nil {
		return group, fmt.Errorf("invalid upload bandwidth: %w", err)
	}
	bandwidthDL, err := strconv.ParseInt(r.Form.Get("download_bandwidth"), 10, 64)
	if err != nil {
		return group, fmt.Errorf("invalid download bandwidth: %w", err)
	}
	dataTransferUL, dataTransferDL, dataTransferTotal, err := getTransferLimits(r)
	if err != nil {
		return group, err
	}
	expiresIn, err := strconv.Atoi(r.Form.Get("expires_in"))
	if err != nil {
		return group, fmt.Errorf("invalid expires in: %w", err)
	}
	fsConfig, err := getFsConfigFromPostFields(r)
	if err != nil {
		return group, err
	}
	filters, err := getFiltersFromUserPostFields(r)
	if err != nil {
		return group, err
	}
	group = dataprovider.Group{
		BaseGroup: sdk.BaseGroup{
			Name:        strings.TrimSpace(r.Form.Get("name")),
			Description: r.Form.Get("description"),
		},
		UserSettings: dataprovider.GroupUserSettings{
			BaseGroupUserSettings: sdk.BaseGroupUserSettings{
				HomeDir:              strings.TrimSpace(r.Form.Get("home_dir")),
				MaxSessions:          maxSessions,
				QuotaSize:            quotaSize,
				QuotaFiles:           quotaFiles,
				Permissions:          getSubDirPermissionsFromPostFields(r),
				UploadBandwidth:      bandwidthUL,
				DownloadBandwidth:    bandwidthDL,
				UploadDataTransfer:   dataTransferUL,
				DownloadDataTransfer: dataTransferDL,
				TotalDataTransfer:    dataTransferTotal,
				ExpiresIn:            expiresIn,
				Filters:              filters,
			},
			FsConfig: fsConfig,
		},
		VirtualFolders: getVirtualFoldersFromPostFields(r),
	}
	return group, nil
}

func getKeyValsFromPostFields(r *http.Request, key, val string) []dataprovider.KeyValue {
	var res []dataprovider.KeyValue

	keys := r.Form[key]
	values := r.Form[val]

	for idx, k := range keys {
		v := values[idx]
		if k != "" && v != "" {
			res = append(res, dataprovider.KeyValue{
				Key:   k,
				Value: v,
			})
		}
	}

	return res
}

func getRenameConfigsFromPostFields(r *http.Request) []dataprovider.RenameConfig {
	var res []dataprovider.RenameConfig
	keys := r.Form["fs_rename_source"]
	values := r.Form["fs_rename_target"]

	for idx, k := range keys {
		v := values[idx]
		if k != "" && v != "" {
			opts := r.Form["fs_rename_options"+strconv.Itoa(idx)]
			res = append(res, dataprovider.RenameConfig{
				KeyValue: dataprovider.KeyValue{
					Key:   k,
					Value: v,
				},
				UpdateModTime: slices.Contains(opts, "1"),
			})
		}
	}

	return res
}

func getFoldersRetentionFromPostFields(r *http.Request) ([]dataprovider.FolderRetention, error) {
	var res []dataprovider.FolderRetention
	paths := r.Form["folder_retention_path"]
	values := r.Form["folder_retention_val"]

	for idx, p := range paths {
		if p != "" {
			retention, err := strconv.Atoi(values[idx])
			if err != nil {
				return nil, fmt.Errorf("invalid retention for path %q: %w", p, err)
			}
			opts := r.Form["folder_retention_options"+strconv.Itoa(idx)]
			res = append(res, dataprovider.FolderRetention{
				Path:            p,
				Retention:       retention,
				DeleteEmptyDirs: slices.Contains(opts, "1"),
			})
		}
	}

	return res, nil
}

func getHTTPPartsFromPostFields(r *http.Request) []dataprovider.HTTPPart {
	var result []dataprovider.HTTPPart

	names := r.Form["http_part_name"]
	files := r.Form["http_part_file"]
	headers := r.Form["http_part_headers"]
	bodies := r.Form["http_part_body"]
	orders := r.Form["http_part_order"]

	for idx, partName := range names {
		if partName != "" {
			order, err := strconv.Atoi(orders[idx])
			if err == nil {
				filePath := files[idx]
				body := bodies[idx]
				concatHeaders := getSliceFromDelimitedValues(headers[idx], "\n")
				var headers []dataprovider.KeyValue
				for _, h := range concatHeaders {
					values := strings.SplitN(h, ":", 2)
					if len(values) > 1 {
						headers = append(headers, dataprovider.KeyValue{
							Key:   strings.TrimSpace(values[0]),
							Value: strings.TrimSpace(values[1]),
						})
					}
				}
				result = append(result, dataprovider.HTTPPart{
					Name:     partName,
					Filepath: filePath,
					Headers:  headers,
					Body:     body,
					Order:    order,
				})
			}
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Order < result[j].Order
	})
	return result
}

func updateRepeaterFormActionFields(r *http.Request) {
	for k := range r.Form {
		if hasPrefixAndSuffix(k, "http_headers[", "][http_header_key]") {
			base, _ := strings.CutSuffix(k, "[http_header_key]")
			r.Form.Add("http_header_key", strings.TrimSpace(r.Form.Get(k)))
			r.Form.Add("http_header_value", strings.TrimSpace(r.Form.Get(base+"[http_header_value]")))
			continue
		}
		if hasPrefixAndSuffix(k, "query_parameters[", "][http_query_key]") {
			base, _ := strings.CutSuffix(k, "[http_query_key]")
			r.Form.Add("http_query_key", strings.TrimSpace(r.Form.Get(k)))
			r.Form.Add("http_query_value", strings.TrimSpace(r.Form.Get(base+"[http_query_value]")))
			continue
		}
		if hasPrefixAndSuffix(k, "multipart_body[", "][http_part_name]") {
			base, _ := strings.CutSuffix(k, "[http_part_name]")
			order, _ := strings.CutPrefix(k, "multipart_body[")
			order, _ = strings.CutSuffix(order, "][http_part_name]")
			r.Form.Add("http_part_name", strings.TrimSpace(r.Form.Get(k)))
			r.Form.Add("http_part_file", strings.TrimSpace(r.Form.Get(base+"[http_part_file]")))
			r.Form.Add("http_part_headers", strings.TrimSpace(r.Form.Get(base+"[http_part_headers]")))
			r.Form.Add("http_part_body", strings.TrimSpace(r.Form.Get(base+"[http_part_body]")))
			r.Form.Add("http_part_order", order)
			continue
		}
		if hasPrefixAndSuffix(k, "env_vars[", "][cmd_env_key]") {
			base, _ := strings.CutSuffix(k, "[cmd_env_key]")
			r.Form.Add("cmd_env_key", strings.TrimSpace(r.Form.Get(k)))
			r.Form.Add("cmd_env_value", strings.TrimSpace(r.Form.Get(base+"[cmd_env_value]")))
			continue
		}
		if hasPrefixAndSuffix(k, "data_retention[", "][folder_retention_path]") {
			base, _ := strings.CutSuffix(k, "[folder_retention_path]")
			r.Form.Add("folder_retention_path", strings.TrimSpace(r.Form.Get(k)))
			r.Form.Add("folder_retention_val", strings.TrimSpace(r.Form.Get(base+"[folder_retention_val]")))
			r.Form["folder_retention_options"+strconv.Itoa(len(r.Form["folder_retention_path"])-1)] =
				r.Form[base+"[folder_retention_options][]"]
			continue
		}
		if hasPrefixAndSuffix(k, "fs_rename[", "][fs_rename_source]") {
			base, _ := strings.CutSuffix(k, "[fs_rename_source]")
			r.Form.Add("fs_rename_source", strings.TrimSpace(r.Form.Get(k)))
			r.Form.Add("fs_rename_target", strings.TrimSpace(r.Form.Get(base+"[fs_rename_target]")))
			r.Form["fs_rename_options"+strconv.Itoa(len(r.Form["fs_rename_source"])-1)] =
				r.Form[base+"[fs_rename_options][]"]
			continue
		}
		if hasPrefixAndSuffix(k, "fs_copy[", "][fs_copy_source]") {
			base, _ := strings.CutSuffix(k, "[fs_copy_source]")
			r.Form.Add("fs_copy_source", strings.TrimSpace(r.Form.Get(k)))
			r.Form.Add("fs_copy_target", strings.TrimSpace(r.Form.Get(base+"[fs_copy_target]")))
			continue
		}
	}
}

func getEventActionOptionsFromPostFields(r *http.Request) (dataprovider.BaseEventActionOptions, error) {
	updateRepeaterFormActionFields(r)
	httpTimeout, err := strconv.Atoi(r.Form.Get("http_timeout"))
	if err != nil {
		return dataprovider.BaseEventActionOptions{}, fmt.Errorf("invalid http timeout: %w", err)
	}
	cmdTimeout, err := strconv.Atoi(r.Form.Get("cmd_timeout"))
	if err != nil {
		return dataprovider.BaseEventActionOptions{}, fmt.Errorf("invalid command timeout: %w", err)
	}
	foldersRetention, err := getFoldersRetentionFromPostFields(r)
	if err != nil {
		return dataprovider.BaseEventActionOptions{}, err
	}
	fsActionType, err := strconv.Atoi(r.Form.Get("fs_action_type"))
	if err != nil {
		return dataprovider.BaseEventActionOptions{}, fmt.Errorf("invalid fs action type: %w", err)
	}
	pwdExpirationThreshold, err := strconv.Atoi(r.Form.Get("pwd_expiration_threshold"))
	if err != nil {
		return dataprovider.BaseEventActionOptions{}, fmt.Errorf("invalid password expiration threshold: %w", err)
	}
	var disableThreshold, deleteThreshold int
	if val, err := strconv.Atoi(r.Form.Get("inactivity_disable_threshold")); err == nil {
		disableThreshold = val
	}
	if val, err := strconv.Atoi(r.Form.Get("inactivity_delete_threshold")); err == nil {
		deleteThreshold = val
	}
	var emailAttachments []string
	if r.Form.Get("email_attachments") != "" {
		emailAttachments = getSliceFromDelimitedValues(r.Form.Get("email_attachments"), ",")
	}
	var cmdArgs []string
	if r.Form.Get("cmd_arguments") != "" {
		cmdArgs = getSliceFromDelimitedValues(r.Form.Get("cmd_arguments"), ",")
	}
	idpMode := 0
	if r.Form.Get("idp_mode") == "1" {
		idpMode = 1
	}
	emailContentType := 0
	if r.Form.Get("email_content_type") == "1" {
		emailContentType = 1
	}
	options := dataprovider.BaseEventActionOptions{
		HTTPConfig: dataprovider.EventActionHTTPConfig{
			Endpoint:        strings.TrimSpace(r.Form.Get("http_endpoint")),
			Username:        strings.TrimSpace(r.Form.Get("http_username")),
			Password:        getSecretFromFormField(r, "http_password"),
			Headers:         getKeyValsFromPostFields(r, "http_header_key", "http_header_value"),
			Timeout:         httpTimeout,
			SkipTLSVerify:   r.Form.Get("http_skip_tls_verify") != "",
			Method:          r.Form.Get("http_method"),
			QueryParameters: getKeyValsFromPostFields(r, "http_query_key", "http_query_value"),
			Body:            r.Form.Get("http_body"),
			Parts:           getHTTPPartsFromPostFields(r),
		},
		CmdConfig: dataprovider.EventActionCommandConfig{
			Cmd:     strings.TrimSpace(r.Form.Get("cmd_path")),
			Args:    cmdArgs,
			Timeout: cmdTimeout,
			EnvVars: getKeyValsFromPostFields(r, "cmd_env_key", "cmd_env_value"),
		},
		EmailConfig: dataprovider.EventActionEmailConfig{
			Recipients:  getSliceFromDelimitedValues(r.Form.Get("email_recipients"), ","),
			Bcc:         getSliceFromDelimitedValues(r.Form.Get("email_bcc"), ","),
			Subject:     r.Form.Get("email_subject"),
			ContentType: emailContentType,
			Body:        r.Form.Get("email_body"),
			Attachments: emailAttachments,
		},
		RetentionConfig: dataprovider.EventActionDataRetentionConfig{
			Folders: foldersRetention,
		},
		FsConfig: dataprovider.EventActionFilesystemConfig{
			Type:    fsActionType,
			Renames: getRenameConfigsFromPostFields(r),
			Deletes: getSliceFromDelimitedValues(r.Form.Get("fs_delete_paths"), ","),
			MkDirs:  getSliceFromDelimitedValues(r.Form.Get("fs_mkdir_paths"), ","),
			Exist:   getSliceFromDelimitedValues(r.Form.Get("fs_exist_paths"), ","),
			Copy:    getKeyValsFromPostFields(r, "fs_copy_source", "fs_copy_target"),
			Compress: dataprovider.EventActionFsCompress{
				Name:  strings.TrimSpace(r.Form.Get("fs_compress_name")),
				Paths: getSliceFromDelimitedValues(r.Form.Get("fs_compress_paths"), ","),
			},
		},
		PwdExpirationConfig: dataprovider.EventActionPasswordExpiration{
			Threshold: pwdExpirationThreshold,
		},
		UserInactivityConfig: dataprovider.EventActionUserInactivity{
			DisableThreshold: disableThreshold,
			DeleteThreshold:  deleteThreshold,
		},
		IDPConfig: dataprovider.EventActionIDPAccountCheck{
			Mode:          idpMode,
			TemplateUser:  strings.TrimSpace(r.Form.Get("idp_user")),
			TemplateAdmin: strings.TrimSpace(r.Form.Get("idp_admin")),
		},
	}
	return options, nil
}

func getEventActionFromPostFields(r *http.Request) (dataprovider.BaseEventAction, error) {
	err := r.ParseForm()
	if err != nil {
		return dataprovider.BaseEventAction{}, util.NewI18nError(err, util.I18nErrorInvalidForm)
	}
	actionType, err := strconv.Atoi(r.Form.Get("type"))
	if err != nil {
		return dataprovider.BaseEventAction{}, fmt.Errorf("invalid action type: %w", err)
	}
	options, err := getEventActionOptionsFromPostFields(r)
	if err != nil {
		return dataprovider.BaseEventAction{}, err
	}
	action := dataprovider.BaseEventAction{
		Name:        strings.TrimSpace(r.Form.Get("name")),
		Description: r.Form.Get("description"),
		Type:        actionType,
		Options:     options,
	}
	return action, nil
}

func getIDPLoginEventFromPostField(r *http.Request) int {
	switch r.Form.Get("idp_login_event") {
	case "1":
		return 1
	case "2":
		return 2
	default:
		return 0
	}
}

func getEventRuleConditionsFromPostFields(r *http.Request) (dataprovider.EventConditions, error) {
	var schedules []dataprovider.Schedule
	var names, groupNames, roleNames, fsPaths []dataprovider.ConditionPattern

	scheduleHours := r.Form["schedule_hour"]
	scheduleDayOfWeeks := r.Form["schedule_day_of_week"]
	scheduleDayOfMonths := r.Form["schedule_day_of_month"]
	scheduleMonths := r.Form["schedule_month"]

	for idx, hour := range scheduleHours {
		if hour != "" {
			schedules = append(schedules, dataprovider.Schedule{
				Hours:      hour,
				DayOfWeek:  scheduleDayOfWeeks[idx],
				DayOfMonth: scheduleDayOfMonths[idx],
				Month:      scheduleMonths[idx],
			})
		}
	}

	for idx, name := range r.Form["name_pattern"] {
		if name != "" {
			names = append(names, dataprovider.ConditionPattern{
				Pattern:      name,
				InverseMatch: r.Form["type_name_pattern"][idx] == inversePatternType,
			})
		}
	}

	for idx, name := range r.Form["group_name_pattern"] {
		if name != "" {
			groupNames = append(groupNames, dataprovider.ConditionPattern{
				Pattern:      name,
				InverseMatch: r.Form["type_group_name_pattern"][idx] == inversePatternType,
			})
		}
	}

	for idx, name := range r.Form["role_name_pattern"] {
		if name != "" {
			roleNames = append(roleNames, dataprovider.ConditionPattern{
				Pattern:      name,
				InverseMatch: r.Form["type_role_name_pattern"][idx] == inversePatternType,
			})
		}
	}

	for idx, name := range r.Form["fs_path_pattern"] {
		if name != "" {
			fsPaths = append(fsPaths, dataprovider.ConditionPattern{
				Pattern:      name,
				InverseMatch: r.Form["type_fs_path_pattern"][idx] == inversePatternType,
			})
		}
	}

	minFileSize, err := util.ParseBytes(r.Form.Get("fs_min_size"))
	if err != nil {
		return dataprovider.EventConditions{}, util.NewI18nError(fmt.Errorf("invalid min file size: %w", err), util.I18nErrorInvalidMinSize)
	}
	maxFileSize, err := util.ParseBytes(r.Form.Get("fs_max_size"))
	if err != nil {
		return dataprovider.EventConditions{}, util.NewI18nError(fmt.Errorf("invalid max file size: %w", err), util.I18nErrorInvalidMaxSize)
	}
	var eventStatuses []int
	for _, s := range r.Form["fs_statuses"] {
		status, err := strconv.ParseInt(s, 10, 32)
		if err == nil {
			eventStatuses = append(eventStatuses, int(status))
		}
	}
	conditions := dataprovider.EventConditions{
		FsEvents:       r.Form["fs_events"],
		ProviderEvents: r.Form["provider_events"],
		IDPLoginEvent:  getIDPLoginEventFromPostField(r),
		Schedules:      schedules,
		Options: dataprovider.ConditionOptions{
			Names:               names,
			GroupNames:          groupNames,
			RoleNames:           roleNames,
			FsPaths:             fsPaths,
			Protocols:           r.Form["fs_protocols"],
			EventStatuses:       eventStatuses,
			ProviderObjects:     r.Form["provider_objects"],
			MinFileSize:         minFileSize,
			MaxFileSize:         maxFileSize,
			ConcurrentExecution: r.Form.Get("concurrent_execution") != "",
		},
	}
	return conditions, nil
}

func getEventRuleActionsFromPostFields(r *http.Request) []dataprovider.EventAction {
	var actions []dataprovider.EventAction

	names := r.Form["action_name"]
	orders := r.Form["action_order"]

	for idx, name := range names {
		if name != "" {
			order, err := strconv.Atoi(orders[idx])
			if err == nil {
				options := r.Form["action_options"+strconv.Itoa(idx)]
				actions = append(actions, dataprovider.EventAction{
					BaseEventAction: dataprovider.BaseEventAction{
						Name: name,
					},
					Order: order + 1,
					Options: dataprovider.EventActionOptions{
						IsFailureAction: slices.Contains(options, "1"),
						StopOnFailure:   slices.Contains(options, "2"),
						ExecuteSync:     slices.Contains(options, "3"),
					},
				})
			}
		}
	}

	return actions
}

func updateRepeaterFormRuleFields(r *http.Request) {
	for k := range r.Form {
		if hasPrefixAndSuffix(k, "schedules[", "][schedule_hour]") {
			base, _ := strings.CutSuffix(k, "[schedule_hour]")
			r.Form.Add("schedule_hour", strings.TrimSpace(r.Form.Get(k)))
			r.Form.Add("schedule_day_of_week", strings.TrimSpace(r.Form.Get(base+"[schedule_day_of_week]")))
			r.Form.Add("schedule_day_of_month", strings.TrimSpace(r.Form.Get(base+"[schedule_day_of_month]")))
			r.Form.Add("schedule_month", strings.TrimSpace(r.Form.Get(base+"[schedule_month]")))
			continue
		}
		if hasPrefixAndSuffix(k, "name_filters[", "][name_pattern]") {
			base, _ := strings.CutSuffix(k, "[name_pattern]")
			r.Form.Add("name_pattern", strings.TrimSpace(r.Form.Get(k)))
			r.Form.Add("type_name_pattern", strings.TrimSpace(r.Form.Get(base+"[type_name_pattern]")))
			continue
		}
		if hasPrefixAndSuffix(k, "group_name_filters[", "][group_name_pattern]") {
			base, _ := strings.CutSuffix(k, "[group_name_pattern]")
			r.Form.Add("group_name_pattern", strings.TrimSpace(r.Form.Get(k)))
			r.Form.Add("type_group_name_pattern", strings.TrimSpace(r.Form.Get(base+"[type_group_name_pattern]")))
			continue
		}
		if hasPrefixAndSuffix(k, "role_name_filters[", "][role_name_pattern]") {
			base, _ := strings.CutSuffix(k, "[role_name_pattern]")
			r.Form.Add("role_name_pattern", strings.TrimSpace(r.Form.Get(k)))
			r.Form.Add("type_role_name_pattern", strings.TrimSpace(r.Form.Get(base+"[type_role_name_pattern]")))
			continue
		}
		if hasPrefixAndSuffix(k, "path_filters[", "][fs_path_pattern]") {
			base, _ := strings.CutSuffix(k, "[fs_path_pattern]")
			r.Form.Add("fs_path_pattern", strings.TrimSpace(r.Form.Get(k)))
			r.Form.Add("type_fs_path_pattern", strings.TrimSpace(r.Form.Get(base+"[type_fs_path_pattern]")))
			continue
		}
		if hasPrefixAndSuffix(k, "actions[", "][action_name]") {
			base, _ := strings.CutSuffix(k, "[action_name]")
			order, _ := strings.CutPrefix(k, "actions[")
			order, _ = strings.CutSuffix(order, "][action_name]")
			r.Form.Add("action_name", strings.TrimSpace(r.Form.Get(k)))
			r.Form["action_options"+strconv.Itoa(len(r.Form["action_name"])-1)] = r.Form[base+"[action_options][]"]
			r.Form.Add("action_order", order)
			continue
		}
	}
}

func getEventRuleFromPostFields(r *http.Request) (dataprovider.EventRule, error) {
	err := r.ParseForm()
	if err != nil {
		return dataprovider.EventRule{}, util.NewI18nError(err, util.I18nErrorInvalidForm)
	}
	updateRepeaterFormRuleFields(r)
	status, err := strconv.Atoi(r.Form.Get("status"))
	if err != nil {
		return dataprovider.EventRule{}, fmt.Errorf("invalid status: %w", err)
	}
	trigger, err := strconv.Atoi(r.Form.Get("trigger"))
	if err != nil {
		return dataprovider.EventRule{}, fmt.Errorf("invalid trigger: %w", err)
	}
	conditions, err := getEventRuleConditionsFromPostFields(r)
	if err != nil {
		return dataprovider.EventRule{}, err
	}
	rule := dataprovider.EventRule{
		Name:        strings.TrimSpace(r.Form.Get("name")),
		Status:      status,
		Description: r.Form.Get("description"),
		Trigger:     trigger,
		Conditions:  conditions,
		Actions:     getEventRuleActionsFromPostFields(r),
	}
	return rule, nil
}

func getRoleFromPostFields(r *http.Request) (dataprovider.Role, error) {
	err := r.ParseForm()
	if err != nil {
		return dataprovider.Role{}, util.NewI18nError(err, util.I18nErrorInvalidForm)
	}

	return dataprovider.Role{
		Name:        strings.TrimSpace(r.Form.Get("name")),
		Description: r.Form.Get("description"),
	}, nil
}

func getIPListEntryFromPostFields(r *http.Request, listType dataprovider.IPListType) (dataprovider.IPListEntry, error) {
	err := r.ParseForm()
	if err != nil {
		return dataprovider.IPListEntry{}, util.NewI18nError(err, util.I18nErrorInvalidForm)
	}
	var mode int
	if listType == dataprovider.IPListTypeDefender {
		mode, err = strconv.Atoi(r.Form.Get("mode"))
		if err != nil {
			return dataprovider.IPListEntry{}, fmt.Errorf("invalid mode: %w", err)
		}
	} else {
		mode = 1
	}
	protocols := 0
	for _, proto := range r.Form["protocols"] {
		p, err := strconv.Atoi(proto)
		if err == nil {
			protocols += p
		}
	}

	return dataprovider.IPListEntry{
		IPOrNet:     strings.TrimSpace(r.Form.Get("ipornet")),
		Mode:        mode,
		Protocols:   protocols,
		Description: r.Form.Get("description"),
	}, nil
}

func getSFTPConfigsFromPostFields(r *http.Request) *dataprovider.SFTPDConfigs {
	return &dataprovider.SFTPDConfigs{
		HostKeyAlgos:   r.Form["sftp_host_key_algos"],
		PublicKeyAlgos: r.Form["sftp_pub_key_algos"],
		KexAlgorithms:  r.Form["sftp_kex_algos"],
		Ciphers:        r.Form["sftp_ciphers"],
		MACs:           r.Form["sftp_macs"],
	}
}

func getACMEConfigsFromPostFields(r *http.Request) *dataprovider.ACMEConfigs {
	port, err := strconv.Atoi(r.Form.Get("acme_port"))
	if err != nil {
		port = 80
	}
	var protocols int
	for _, val := range r.Form["acme_protocols"] {
		switch val {
		case "1":
			protocols++
		case "2":
			protocols += 2
		case "3":
			protocols += 4
		}
	}

	return &dataprovider.ACMEConfigs{
		Domain:          strings.TrimSpace(r.Form.Get("acme_domain")),
		Email:           strings.TrimSpace(r.Form.Get("acme_email")),
		HTTP01Challenge: dataprovider.ACMEHTTP01Challenge{Port: port},
		Protocols:       protocols,
	}
}

func getSMTPConfigsFromPostFields(r *http.Request) *dataprovider.SMTPConfigs {
	port, err := strconv.Atoi(r.Form.Get("smtp_port"))
	if err != nil {
		port = 587
	}
	authType, err := strconv.Atoi(r.Form.Get("smtp_auth"))
	if err != nil {
		authType = 0
	}
	encryption, err := strconv.Atoi(r.Form.Get("smtp_encryption"))
	if err != nil {
		encryption = 0
	}
	debug := 0
	if r.Form.Get("smtp_debug") != "" {
		debug = 1
	}
	oauth2Provider := 0
	if r.Form.Get("smtp_oauth2_provider") == "1" {
		oauth2Provider = 1
	}
	return &dataprovider.SMTPConfigs{
		Host:       strings.TrimSpace(r.Form.Get("smtp_host")),
		Port:       port,
		From:       strings.TrimSpace(r.Form.Get("smtp_from")),
		User:       strings.TrimSpace(r.Form.Get("smtp_username")),
		Password:   getSecretFromFormField(r, "smtp_password"),
		AuthType:   authType,
		Encryption: encryption,
		Domain:     strings.TrimSpace(r.Form.Get("smtp_domain")),
		Debug:      debug,
		OAuth2: dataprovider.SMTPOAuth2{
			Provider:     oauth2Provider,
			Tenant:       strings.TrimSpace(r.Form.Get("smtp_oauth2_tenant")),
			ClientID:     strings.TrimSpace(r.Form.Get("smtp_oauth2_client_id")),
			ClientSecret: getSecretFromFormField(r, "smtp_oauth2_client_secret"),
			RefreshToken: getSecretFromFormField(r, "smtp_oauth2_refresh_token"),
		},
	}
}

func getImageInputBytes(r *http.Request, fieldName, removeFieldName string, defaultVal []byte) ([]byte, error) {
	var result []byte
	remove := r.Form.Get(removeFieldName)
	if remove == "" || remove == "0" {
		result = defaultVal
	}
	f, _, err := r.FormFile(fieldName)
	if err != nil {
		if errors.Is(err, http.ErrMissingFile) {
			return result, nil
		}
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(f)
}

func getBrandingConfigFromPostFields(r *http.Request, config *dataprovider.BrandingConfigs) (
	*dataprovider.BrandingConfigs, error,
) {
	if config == nil {
		config = &dataprovider.BrandingConfigs{}
	}
	adminLogo, err := getImageInputBytes(r, "branding_webadmin_logo", "branding_webadmin_logo_remove", config.WebAdmin.Logo)
	if err != nil {
		return nil, util.NewI18nError(err, util.I18nErrorInvalidForm)
	}
	adminFavicon, err := getImageInputBytes(r, "branding_webadmin_favicon", "branding_webadmin_favicon_remove",
		config.WebAdmin.Favicon)
	if err != nil {
		return nil, util.NewI18nError(err, util.I18nErrorInvalidForm)
	}
	clientLogo, err := getImageInputBytes(r, "branding_webclient_logo", "branding_webclient_logo_remove",
		config.WebClient.Logo)
	if err != nil {
		return nil, util.NewI18nError(err, util.I18nErrorInvalidForm)
	}
	clientFavicon, err := getImageInputBytes(r, "branding_webclient_favicon", "branding_webclient_favicon_remove",
		config.WebClient.Favicon)
	if err != nil {
		return nil, util.NewI18nError(err, util.I18nErrorInvalidForm)
	}

	branding := &dataprovider.BrandingConfigs{
		WebAdmin: dataprovider.BrandingConfig{
			Name:           strings.TrimSpace(r.Form.Get("branding_webadmin_name")),
			ShortName:      strings.TrimSpace(r.Form.Get("branding_webadmin_short_name")),
			Logo:           adminLogo,
			Favicon:        adminFavicon,
			DisclaimerName: strings.TrimSpace(r.Form.Get("branding_webadmin_disclaimer_name")),
			DisclaimerURL:  strings.TrimSpace(r.Form.Get("branding_webadmin_disclaimer_url")),
		},
		WebClient: dataprovider.BrandingConfig{
			Name:           strings.TrimSpace(r.Form.Get("branding_webclient_name")),
			ShortName:      strings.TrimSpace(r.Form.Get("branding_webclient_short_name")),
			Logo:           clientLogo,
			Favicon:        clientFavicon,
			DisclaimerName: strings.TrimSpace(r.Form.Get("branding_webclient_disclaimer_name")),
			DisclaimerURL:  strings.TrimSpace(r.Form.Get("branding_webclient_disclaimer_url")),
		},
	}
	return branding, nil
}

