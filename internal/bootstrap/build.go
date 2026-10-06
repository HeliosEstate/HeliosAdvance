// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"strconv"
)

func validateFields(fields Fields) error {
	bad := func(field string) error { return &Refusal{Cause: FieldMalformed, Field: field} }
	if fields.Server == 0 {
		return bad(FieldServer)
	}
	if fields.Connection == "" {
		return bad(FieldConnection)
	}
	if fields.AccountName == "" {
		return bad(FieldAccountName)
	}
	if len(fields.VaultKeys) == 0 || len(fields.VaultKeys) > 2 {
		return bad(FieldVaultKeyPrefix)
	}
	seen := map[uint32]bool{}
	for _, key := range fields.VaultKeys {
		name := FieldVaultKeyPrefix + strconv.FormatUint(uint64(key.Version), 10)
		if key.Version == 0 || seen[key.Version] || len(key.Key) != vaultKey {
			return bad(name)
		}
		seen[key.Version] = true
	}
	if len(fields.ReceivingKey) == 0 {
		return bad(FieldReceivingKey)
	}
	if len(fields.SigningKey) == 0 {
		return bad(FieldSigningKey)
	}
	return nil
}
