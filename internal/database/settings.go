// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package database

import "strconv"

const settingCount = 6

// settingColumns are the six settings in the contract's order: a boolean for each on-or-off setting
// and an integer for each port, alternately.
var settingColumns = [settingCount]string{"telnet_on", "telnet_port", "ssh_on", "ssh_port", "telnets_on", "telnets_port"}

// settingsSQL reads each setting as text only while its column is of its kind and NULL otherwise,
// as checkSchemaVersion reads the version, so a column whose type was changed never fails to scan.
var settingsSQL = func() string {
	list := ""
	for index, column := range settingColumns {
		if index > 0 {
			list += ", "
		}
		kind := "boolean"
		if index%2 == 1 {
			kind = "integer"
		}
		list += "CASE WHEN pg_typeof(" + column + ") = '" + kind + "'::regtype THEN " + column + "::text END"
	}
	return list
}()

// parseSettings checks each setting where it arrives, since turning the database's integer into a
// port would wrap silently (70000 would become 4464). The first one NULL, or refused by its kind,
// is named.
func parseSettings(texts [settingCount]*string) (Settings, error) {
	var switches [3]bool
	var port [3]uint16
	for index, text := range texts {
		if text == nil {
			return Settings{}, &SettingError{Setting: settingColumns[index]}
		}
		if index%2 == 0 {
			value, err := strconv.ParseBool(*text)
			if err != nil {
				return Settings{}, &SettingError{Setting: settingColumns[index]}
			}
			switches[index/2] = value
			continue
		}
		value, err := strconv.ParseUint(*text, 10, 16)
		if err != nil {
			return Settings{}, &SettingError{Setting: settingColumns[index]}
		}
		port[index/2] = uint16(value)
	}
	return Settings{TelnetOn: switches[0], TelnetPort: port[0], SSHOn: switches[1], SSHPort: port[1],
		TelnetsOn: switches[2], TelnetsPort: port[2]}, nil
}
