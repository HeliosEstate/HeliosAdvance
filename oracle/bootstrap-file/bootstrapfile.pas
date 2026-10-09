{ SPDX-FileCopyrightText: 2026 Pascal Fairchild
  SPDX-License-Identifier: AGPL-3.0-only }

{ The bootstrap file oracle: a second reader and writer of bootstrap file format 1, written
  from the format's description alone and never from the engine's code. Where the two
  disagree about a file, one of them misread the description. Usage is in README.md. }
program BootstrapFile;

{$mode objfpc}{$H+}{$R+}{$Q+}

uses
  SysUtils, Classes, AesGcm, RecordList;

const
  WholeFileLimit = 65536;
  { The record list is ours and small; a bound keeps a wrong path from reading a disk image. }
  RecordListLimit = 16 * 1024 * 1024;
  KeyFileLimit = 1024;

  ExitUsage = 1;
  { The engine's codes for a file: 2 is ErrFormat, 3 ErrInvalid, 4 ErrDecrypt. }
  ExitFormat = 2;
  ExitInvalid = 3;
  ExitDecrypt = 4;

  VaultKeyPrefix = 'vault.key.';

  { The key holders the header may name, and the sealed key each carries. }
  WindowsKeyStore = 1;
  SwarmSecret = 5;
  WindowsKeyNameLength = 37;
  WindowsSealedLength = WindowsKeyNameLength + 256;
  SystemdCredentialMax = 4096;

type
  EUsage = class(Exception);

  { Read's verdicts carry the exit code the tests branch on. }
  ERefusal = class(Exception)
  public
    ExitStatus: Integer;
    constructor CreateRefusal(Code: Integer; const Reason: string);
  end;

constructor ERefusal.CreateRefusal(Code: Integer; const Reason: string);
begin
  inherited Create(Reason);
  ExitStatus := Code;
end;

{ At most Limit + 1 bytes, so a caller can tell "exactly Limit" from "more". }
function ReadBounded(const Path: string; Limit: Integer): TBytes;
var
  Stream: TStream;
  Total, Count: Integer;
begin
  if Path = '-' then
    Stream := THandleStream.Create(StdInputHandle)
  else
    Stream := TFileStream.Create(Path, fmOpenRead or fmShareDenyWrite);
  try
    Result := nil;
    SetLength(Result, Limit + 1);
    Total := 0;
    repeat
      Count := Stream.Read(Result[Total], Length(Result) - Total);
      Inc(Total, Count);
    until (Count = 0) or (Total = Length(Result));
    SetLength(Result, Total);
  finally
    Stream.Free;
  end;
end;

procedure WriteWhole(const Path: string; const Data: TBytes);
var
  Stream: TStream;
begin
  if Path = '-' then
    Stream := THandleStream.Create(StdOutputHandle)
  else
    Stream := TFileStream.Create(Path, fmCreate);
  try
    if Length(Data) > 0 then
      Stream.WriteBuffer(Data[0], Length(Data));
  finally
    Stream.Free;
  end;
end;

function DecodeBase64(const Text: string; out Decoded: TBytes): Boolean;
const
  Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
var
  Index, Value, Bits, BitCount, Padding: Integer;
begin
  Decoded := nil;
  if (Length(Text) = 0) or (Length(Text) mod 4 <> 0) then
    Exit(False);
  Padding := 0;
  while (Padding < 2) and (Text[Length(Text) - Padding] = '=') do
    Inc(Padding);
  Bits := 0;
  BitCount := 0;
  for Index := 1 to Length(Text) - Padding do
  begin
    Value := Pos(Text[Index], Alphabet) - 1;
    if Value < 0 then
      Exit(False);
    Bits := ((Bits shl 6) or Value) and $FFFFFF;
    Inc(BitCount, 6);
    if BitCount >= 8 then
    begin
      Dec(BitCount, 8);
      SetLength(Decoded, Length(Decoded) + 1);
      Decoded[High(Decoded)] := Byte((Bits shr BitCount) and $FF);
    end;
  end;
  Result := True;
end;

function NameText(const Name: TBytes): string;
begin
  SetLength(Result, Length(Name));
  if Length(Name) > 0 then
    Move(Name[0], Result[1], Length(Name));
end;

{ The engine's key-file form, 32 bytes as base64 in 44 characters, so the test key beside
  the sample files serves both programs; 64 hex digits are taken too, for a key typed into
  a test. The oracle checks no key file: surrounding whitespace is ignored. }
function LoadKey(const Path: string): TAesKey;
var
  Raw, Decoded: TBytes;
  Text: string;
  Index, HighValue, LowValue: Integer;
begin
  Raw := ReadBounded(Path, KeyFileLimit);
  if Length(Raw) > KeyFileLimit then
    raise EUsage.CreateFmt('%s: more than %d bytes; not a key', [Path, KeyFileLimit]);
  Text := Trim(NameText(Raw));
  Decoded := nil;
  if Length(Text) = 2 * KeyLength then
  begin
    SetLength(Decoded, KeyLength);
    for Index := 0 to KeyLength - 1 do
    begin
      if not ((Text[2 * Index + 1] in ['0'..'9', 'a'..'f', 'A'..'F'])
        and (Text[2 * Index + 2] in ['0'..'9', 'a'..'f', 'A'..'F'])) then
        raise EUsage.CreateFmt('%s: 64 characters but not hex', [Path]);
      HighValue := StrToInt('$' + Text[2 * Index + 1]);
      LowValue := StrToInt('$' + Text[2 * Index + 2]);
      Decoded[Index] := Byte(HighValue * 16 + LowValue);
    end;
  end
  else if not DecodeBase64(Text, Decoded) or (Length(Decoded) <> KeyLength) then
    raise EUsage.CreateFmt('%s: not 32 bytes as base64 or hex', [Path]);
  Move(Decoded[0], Result, KeyLength);
  FillChar(Decoded[0], Length(Decoded), 0);
end;

function SealPlan(const Key: TAesKey; const Plan: TFilePlan): TBytes;
var
  Header, Sealed: TBytes;
  Nonce: TNonce;
  Edit: TFileEdit;
  OldLength: SizeInt;
  SealedLength: Word;
begin
  if Plan.NonceGiven then
    Nonce := Plan.Nonce
  else
    FillRandom(Nonce, NonceLength);
  if Plan.SealedLengthGiven then
    SealedLength := Plan.SealedLength
  else if Length(Plan.SealedKey) > High(Word) then
    raise EUsage.CreateFmt('the sealed key is %d bytes; its 2-byte length holds at most %d',
      [Length(Plan.SealedKey), High(Word)])
  else
    SealedLength := Length(Plan.SealedKey);
  { The header, then the nonce: every byte before the records. }
  SetLength(Header, HeaderStartLength + Length(Plan.SealedKey) + NonceLength);
  Move(Plan.Magic[0], Header[0], MagicLength);
  Header[MagicLength] := Byte(Plan.Version shr 8);
  Header[MagicLength + 1] := Byte(Plan.Version and $FF);
  Header[MagicLength + 2] := Plan.KeyHolder;
  Header[MagicLength + 3] := Byte(SealedLength shr 8);
  Header[MagicLength + 4] := Byte(SealedLength and $FF);
  if Length(Plan.SealedKey) > 0 then
    Move(Plan.SealedKey[0], Header[HeaderStartLength], Length(Plan.SealedKey));
  Move(Nonce, Header[HeaderStartLength + Length(Plan.SealedKey)], NonceLength);
  { The additional data is every byte before the records as written, a wrong header
    included, so a file with a bad header still carries a tag that verifies. }
  Sealed := Seal(Key, Nonce, Header, Plan.Plaintext);
  Result := Concat(Header, Sealed);
  for Edit in Plan.Edits do
    case Edit.Kind of
      EditTruncate:
        if Edit.Offset < Length(Result) then
          SetLength(Result, Edit.Offset);
      EditFlip:
        begin
          if Edit.Offset >= Length(Result) then
            raise EUsage.CreateFmt('flip %d: the file is %d bytes',
              [Edit.Offset, Length(Result)]);
          Result[Edit.Offset] := Result[Edit.Offset] xor 1;
        end;
      EditAppend:
        begin
          OldLength := Length(Result);
          SetLength(Result, OldLength + Length(Edit.Data));
          if Length(Edit.Data) > 0 then
            Move(Edit.Data[0], Result[OldLength], Length(Edit.Data));
        end;
    end;
end;

procedure RunWrite(const KeyPath, ListPath, OutputPath: string);
var
  Key: TAesKey;
  Raw: TBytes;
  Plan: TFilePlan;
begin
  Key := LoadKey(KeyPath);
  Raw := ReadBounded(ListPath, RecordListLimit);
  if Length(Raw) > RecordListLimit then
    raise EUsage.CreateFmt('%s: more than %d bytes', [ListPath, RecordListLimit]);
  Plan := ParseRecordList(NameText(Raw));
  WriteWhole(OutputPath, SealPlan(Key, Plan));
  FillChar(Key, SizeOf(Key), 0);
end;

type
  TRecordEntry = record
    Name, Data: TBytes;
  end;

function ReadNumber(const Plaintext: TBytes; Offset, Width: Integer): LongWord;
var
  Index: Integer;
begin
  Result := 0;
  for Index := 0 to Width - 1 do
    Result := (Result shl 8) or Plaintext[Offset + Index];
end;

{ The plaintext's framing. Any break in it ends the reading: past that point the bytes are
  no longer records. }
function SplitRecords(const Plaintext: TBytes): specialize TArray<TRecordEntry>;
var
  Offset, Other: Integer;
  NameLength: Integer;
  DataLength: Int64;
  Entry: TRecordEntry;
begin
  Result := nil;
  Offset := 0;
  while Offset < Length(Plaintext) do
  begin
    if Length(Plaintext) - Offset < 2 then
      raise ERefusal.CreateRefusal(ExitInvalid, Format(
        'record %d: its name length runs past the end', [Length(Result) + 1]));
    NameLength := ReadNumber(Plaintext, Offset, 2);
    Inc(Offset, 2);
    if Length(Plaintext) - Offset < NameLength then
      raise ERefusal.CreateRefusal(ExitInvalid, Format(
        'record %d: its name runs past the end', [Length(Result) + 1]));
    Entry.Name := Copy(Plaintext, Offset, NameLength);
    Inc(Offset, NameLength);
    if Length(Plaintext) - Offset < 4 then
      raise ERefusal.CreateRefusal(ExitInvalid, Format(
        'record %d: its data length runs past the end', [Length(Result) + 1]));
    DataLength := ReadNumber(Plaintext, Offset, 4);
    Inc(Offset, 4);
    if Length(Plaintext) - Offset < DataLength then
      raise ERefusal.CreateRefusal(ExitInvalid, Format(
        'record %d: its data runs past the end', [Length(Result) + 1]));
    Entry.Data := Copy(Plaintext, Offset, DataLength);
    Inc(Offset, DataLength);
    if NameLength = 0 then
      raise ERefusal.CreateRefusal(ExitInvalid, Format(
        'record %d: its name is empty', [Length(Result) + 1]));
    if NameLength > 255 then
      raise ERefusal.CreateRefusal(ExitInvalid, Format(
        'record %d: its name is %d bytes; the most is 255', [Length(Result) + 1, NameLength]));
    if not IsValidUtf8(Entry.Name) then
      raise ERefusal.CreateRefusal(ExitInvalid, Format(
        'record %d: its name is not UTF-8', [Length(Result) + 1]));
    for Other := 0 to High(Result) do
      if (Length(Result[Other].Name) = NameLength)
        and CompareMem(@Result[Other].Name[0], @Entry.Name[0], NameLength) then
        raise ERefusal.CreateRefusal(ExitInvalid, Format(
          'record %d: its name %s is also record %d''s',
          [Length(Result) + 1, FormatValue(Entry.Name), Other + 1]));
    SetLength(Result, Length(Result) + 1);
    Result[High(Result)] := Entry;
  end;
end;

{ The prefix is reserved: every name under it is a vault key or a malformed field, never an
  unknown record. }
function HasVaultKeyPrefix(const Name: string): Boolean;
begin
  Result := Copy(Name, 1, Length(VaultKeyPrefix)) = VaultKeyPrefix;
end;

{ A version has one spelling: decimal, no leading zero, 1 to 4,294,967,295, so no two names
  hold one version. }
function IsVaultKeyName(const Name: string): Boolean;
var
  Digits: string;
  Index: Integer;
  Version: QWord;
begin
  Digits := Copy(Name, Length(VaultKeyPrefix) + 1, MaxInt);
  if not HasVaultKeyPrefix(Name) or (Digits = '') or (Length(Digits) > 10)
    or (Digits[1] = '0') then
    Exit(False);
  Version := 0;
  for Index := 1 to Length(Digits) do
  begin
    if not (Digits[Index] in ['0'..'9']) then
      Exit(False);
    Version := Version * 10 + QWord(Ord(Digits[Index]) - Ord('0'));
  end;
  Result := Version <= High(LongWord);
end;

{ Every problem with the known fields, not only the first: a test reading the oracle's
  verdict on an engine-written file learns everything that is wrong at once. }
function JudgeKnownFields(const Entries: array of TRecordEntry): TStringList;
const
  RequiredNames: array[0..5] of string = ('server', 'database.connection',
    'database.account.name', 'database.account.password', 'receiving.key', 'signing.key');
var
  Entry: TRecordEntry;
  Name, Required: string;
  Found: Boolean;
  VaultKeyCount: Integer;
begin
  Result := TStringList.Create;
  for Required in RequiredNames do
  begin
    Found := False;
    for Entry in Entries do
      if NameText(Entry.Name) = Required then
        Found := True;
    if not Found then
      Result.Add(Format('the field %s is absent', [Required]));
  end;
  VaultKeyCount := 0;
  for Entry in Entries do
  begin
    Name := NameText(Entry.Name);
    if (Name = 'server') and (Length(Entry.Data) <> 4) then
      Result.Add(Format('server is %d bytes, not 4', [Length(Entry.Data)]))
    { The rules in the table on Fields hold on read too: a server ID of 0, an empty
      connection or account name, an empty password, an empty receiving or signing key. }
    else if (Name = 'server') and (Entry.Data[0] or Entry.Data[1] or Entry.Data[2]
      or Entry.Data[3] = 0) then
      Result.Add('server is 0')
    else if ((Name = 'database.connection') or (Name = 'database.account.name'))
      and not IsValidUtf8(Entry.Data) then
      Result.Add(Format('%s is not UTF-8', [Name]))
    else if ((Name = 'database.connection') or (Name = 'database.account.name')
      or (Name = 'database.account.password') or (Name = 'receiving.key')
      or (Name = 'signing.key')) and (Length(Entry.Data) = 0) then
      Result.Add(Format('%s is empty', [Name]))
    else if IsVaultKeyName(Name) then
    begin
      Inc(VaultKeyCount);
      if Length(Entry.Data) <> KeyLength then
        Result.Add(Format('%s is %d bytes, not 32', [Name, Length(Entry.Data)]));
    end
    else if HasVaultKeyPrefix(Name) then
      Result.Add(Format('%s is under %s but not a version in decimal from 1 to ' +
        '4,294,967,295 with no leading zero', [FormatValue(Entry.Name), VaultKeyPrefix]));
  end;
  if (VaultKeyCount < 1) or (VaultKeyCount > 2) then
    Result.Add(Format('%d vault keys; a file holds one or two', [VaultKeyCount]));
end;

{ A Windows key's name: hadv- and 32 lowercase hex digits, read as bytes, never as a path. }
function IsWindowsKeyName(const Name: TBytes): Boolean;
var
  Index: Integer;
begin
  if (Length(Name) <> WindowsKeyNameLength) or (NameText(Copy(Name, 0, 5)) <> 'hadv-') then
    Exit(False);
  for Index := 5 to High(Name) do
    if not (Chr(Name[Index]) in ['0'..'9', 'a'..'f']) then
      Exit(False);
  Result := True;
end;

{ Each part of the header against the format's table, in the order it lies in the file. Every
  refusal here comes before the key is used. }
procedure CheckHeader(const Whole: TBytes; out Version: Integer; out KeyHolder: Byte;
  out SealedLength: Integer);
begin
  if Length(Whole) > WholeFileLimit then
    raise ERefusal.CreateRefusal(ExitFormat,
      Format('the file is larger than %d bytes', [WholeFileLimit]));
  if Length(Whole) < HeaderStartLength then
    raise ERefusal.CreateRefusal(ExitFormat, Format(
      'the file is %d bytes, shorter than the header''s first %d', [Length(Whole),
      HeaderStartLength]));
  if NameText(Copy(Whole, 0, MagicLength)) <> 'HADVBOOT' then
    raise ERefusal.CreateRefusal(ExitFormat, 'the file does not begin with HADVBOOT');
  Version := ReadNumber(Whole, MagicLength, 2);
  if Version = 0 then
    raise ERefusal.CreateRefusal(ExitFormat, 'the format version is 0');
  if Version > FormatVersion then
    raise ERefusal.CreateRefusal(ExitFormat, Format(
      'the format version is %d; this oracle reads version 1', [Version]));
  KeyHolder := Whole[MagicLength + 2];
  if (KeyHolder < WindowsKeyStore) or (KeyHolder > SwarmSecret) then
    raise ERefusal.CreateRefusal(ExitFormat, Format(
      'the key holder is %d; the format has 1 to 5', [KeyHolder]));
  SealedLength := ReadNumber(Whole, MagicLength + 3, 2);
  case KeyHolder of
    WindowsKeyStore:
      if SealedLength <> WindowsSealedLength then
        raise ERefusal.CreateRefusal(ExitFormat, Format(
          'the sealed key is %d bytes; key holder 1 has exactly %d',
          [SealedLength, WindowsSealedLength]));
    2, 3:
      if (SealedLength < 1) or (SealedLength > SystemdCredentialMax) then
        raise ERefusal.CreateRefusal(ExitFormat, Format(
          'the sealed key is %d bytes; key holder %d has 1 to %d',
          [SealedLength, KeyHolder, SystemdCredentialMax]));
  else
    if SealedLength <> 0 then
      raise ERefusal.CreateRefusal(ExitFormat, Format(
        'the sealed key is %d bytes; key holder %d has none', [SealedLength, KeyHolder]));
  end;
  if Length(Whole) < HeaderStartLength + SealedLength + NonceLength + TagLength then
    raise ERefusal.CreateRefusal(ExitFormat, Format(
      'the file is %d bytes, shorter than its header, nonce and tag', [Length(Whole)]));
  if (KeyHolder = WindowsKeyStore) and not IsWindowsKeyName(
    Copy(Whole, HeaderStartLength, WindowsKeyNameLength)) then
    raise ERefusal.CreateRefusal(ExitFormat,
      'the sealed key does not begin with hadv- and 32 lowercase hex digits');
end;

procedure RunRead(const KeyPath, FilePath: string);
var
  Key: TAesKey;
  Whole, Authenticated, Sealed, Plaintext: TBytes;
  Nonce: TNonce;
  Version, SealedLength, NonceOffset: Integer;
  KeyHolder: Byte;
  Entries: specialize TArray<TRecordEntry>;
  Entry: TRecordEntry;
  Problems: TStringList;
  Problem: string;
begin
  Key := LoadKey(KeyPath);
  Whole := ReadBounded(FilePath, WholeFileLimit);
  CheckHeader(Whole, Version, KeyHolder, SealedLength);
  NonceOffset := HeaderStartLength + SealedLength;
  Authenticated := Copy(Whole, 0, NonceOffset + NonceLength);
  Move(Whole[NonceOffset], Nonce, NonceLength);
  Sealed := Copy(Whole, NonceOffset + NonceLength, Length(Whole) - NonceOffset - NonceLength);
  if not Open(Key, Nonce, Authenticated, Sealed, Plaintext) then
    raise ERefusal.CreateRefusal(ExitDecrypt, 'the GCM tag does not verify');
  FillChar(Key, SizeOf(Key), 0);
  Entries := SplitRecords(Plaintext);
  WriteLn('magic "HADVBOOT"');
  WriteLn('version ', Version);
  WriteLn('holder ', KeyHolder);
  WriteLn('sealed ', FormatValue(Copy(Whole, HeaderStartLength, SealedLength)));
  WriteLn('nonce ', FormatValue(Copy(Whole, NonceOffset, NonceLength)));
  for Entry in Entries do
    WriteLn('record ', FormatValue(Entry.Name), ' ', FormatValue(Entry.Data));
  Problems := JudgeKnownFields(Entries);
  try
    if Problems.Count > 0 then
    begin
      for Problem in Problems do
        WriteLn(StdErr, 'bootstrap-file: ', Problem);
      ExitCode := ExitInvalid;
    end;
  finally
    Problems.Free;
  end;
end;

procedure RunNewKey(const OutputPath: string);
const
  Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
var
  Key: array[0..KeyLength + 1] of Byte;
  Text: string;
  Index, Group: Integer;
begin
  { Two zero bytes past the key make the last group whole; its final character is '='. }
  FillChar(Key, SizeOf(Key), 0);
  FillRandom(Key, KeyLength);
  Text := '';
  Index := 0;
  while Index < KeyLength do
  begin
    Group := (Key[Index] shl 16) or (Key[Index + 1] shl 8) or Key[Index + 2];
    Text := Text + Alphabet[((Group shr 18) and 63) + 1] + Alphabet[((Group shr 12) and 63) + 1]
      + Alphabet[((Group shr 6) and 63) + 1] + Alphabet[(Group and 63) + 1];
    Inc(Index, 3);
  end;
  Text[Length(Text)] := '=';
  WriteWhole(OutputPath, BytesOf(Text + #10));
  FillChar(Key, SizeOf(Key), 0);
end;

function HexToBytes(const Text: string): TBytes;
var
  Index: Integer;
begin
  Result := nil;
  SetLength(Result, Length(Text) div 2);
  for Index := 0 to High(Result) do
    Result[Index] := Byte(StrToInt('$' + Copy(Text, 2 * Index + 1, 2)));
end;

function BytesToHex(const Data: TBytes): string;
var
  Index: Integer;
begin
  Result := '';
  for Index := 0 to High(Data) do
    Result := Result + LowerCase(IntToHex(Data[Index], 2));
end;

{ FIPS-197 appendix C.3, and the AES-256 cases 13 to 16 of McGrew and Viega's GCM
  specification, the vectors NIST's validation suite grew from. }
procedure RunSelftest;
type
  TGcmCase = record
    Name, Key, Nonce, AdditionalData, Plaintext, Expected: string;
  end;
const
  KeyFifteen = 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308';
  PlainFifteen = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72' +
    '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255';
  CipherFifteen = '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa' +
    '8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad';
  { Case 16 is case 15's first 60 bytes, with additional data. }
  PlainSixteen = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72' +
    '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39';
  CipherSixteen = '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa' +
    '8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662';
  Cases: array[0..3] of TGcmCase = (
    (Name: 'GCM test case 13'; Key: '0000000000000000000000000000000000000000000000000000000000000000';
     Nonce: '000000000000000000000000'; AdditionalData: ''; Plaintext: '';
     Expected: '530f8afbc74536b9a963b4f1c4cb738b'),
    (Name: 'GCM test case 14'; Key: '0000000000000000000000000000000000000000000000000000000000000000';
     Nonce: '000000000000000000000000'; AdditionalData: '';
     Plaintext: '00000000000000000000000000000000';
     Expected: 'cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919'),
    (Name: 'GCM test case 15'; Key: KeyFifteen; Nonce: 'cafebabefacedbaddecaf888';
     AdditionalData: ''; Plaintext: PlainFifteen;
     Expected: CipherFifteen + 'b094dac5d93471bdec1a502270e3cc6c'),
    (Name: 'GCM test case 16'; Key: KeyFifteen; Nonce: 'cafebabefacedbaddecaf888';
     AdditionalData: 'feedfacedeadbeeffeedfacedeadbeefabaddad2';
     Plaintext: PlainSixteen; Expected: CipherSixteen + '76fc6ece0f4e1768cddf8853bb2d551b'));
var
  Key: TAesKey;
  Nonce: TNonce;
  Block, Output: TBlock;
  Plaintext, Sealed, Opened, Tampered: TBytes;
  GcmCase: TGcmCase;
  Failures: Integer;
  Expected: string;
begin
  Failures := 0;
  Move(HexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')[0],
    Key, KeyLength);
  Move(HexToBytes('00112233445566778899aabbccddeeff')[0], Block, 16);
  EncryptBlock(Key, Block, Output);
  if BytesToHex(Output) <> '8ea2b7ca516745bfeafc49904b496089' then
  begin
    WriteLn(StdErr, 'bootstrap-file: FIPS-197 C.3 fails');
    Inc(Failures);
  end;
  for GcmCase in Cases do
  begin
    Move(HexToBytes(GcmCase.Key)[0], Key, KeyLength);
    Move(HexToBytes(GcmCase.Nonce)[0], Nonce, NonceLength);
    Plaintext := HexToBytes(GcmCase.Plaintext);
    Expected := GcmCase.Expected;
    Sealed := Seal(Key, Nonce, HexToBytes(GcmCase.AdditionalData), Plaintext);
    if BytesToHex(Sealed) <> Expected then
    begin
      WriteLn(StdErr, 'bootstrap-file: ', GcmCase.Name, ' seals wrong');
      Inc(Failures);
    end;
    if not Open(Key, Nonce, HexToBytes(GcmCase.AdditionalData), Sealed, Opened)
      or (BytesToHex(Opened) <> BytesToHex(Plaintext)) then
    begin
      WriteLn(StdErr, 'bootstrap-file: ', GcmCase.Name, ' does not open');
      Inc(Failures);
    end;
    Tampered := Copy(Sealed, 0, Length(Sealed));
    Tampered[High(Tampered)] := Tampered[High(Tampered)] xor 1;
    if Open(Key, Nonce, HexToBytes(GcmCase.AdditionalData), Tampered, Opened) then
    begin
      WriteLn(StdErr, 'bootstrap-file: ', GcmCase.Name, ' opens with a wrong tag');
      Inc(Failures);
    end;
  end;
  if Failures > 0 then
    raise ERefusal.CreateRefusal(ExitUsage, Format('selftest: %d failures', [Failures]));
  WriteLn('selftest: ok');
end;

procedure ShowUsage;
begin
  WriteLn(StdErr, 'usage: bootstrap-file write KEY RECORDS OUTPUT');
  WriteLn(StdErr, '       bootstrap-file read KEY FILE');
  WriteLn(StdErr, '       bootstrap-file newkey OUTPUT');
  WriteLn(StdErr, '       bootstrap-file selftest');
  WriteLn(StdErr, 'Any path may be - for standard input or output. See README.md.');
end;

begin
  { On Windows the RTL converts Output to the console's code page, which would rewrite a
    quoted value's UTF-8 bytes and break read's promise that write takes its output back. }
  SetTextCodePage(Output, DefaultSystemCodePage);
  try
    if (ParamCount = 4) and (ParamStr(1) = 'write') then
      RunWrite(ParamStr(2), ParamStr(3), ParamStr(4))
    else if (ParamCount = 3) and (ParamStr(1) = 'read') then
      RunRead(ParamStr(2), ParamStr(3))
    else if (ParamCount = 2) and (ParamStr(1) = 'newkey') then
      RunNewKey(ParamStr(2))
    else if (ParamCount = 1) and (ParamStr(1) = 'selftest') then
      RunSelftest
    else
    begin
      ShowUsage;
      ExitCode := ExitUsage;
    end;
  except
    on Refusal: ERefusal do
    begin
      WriteLn(StdErr, 'bootstrap-file: ', Refusal.Message);
      ExitCode := Refusal.ExitStatus;
    end;
    on Failure: Exception do
    begin
      WriteLn(StdErr, 'bootstrap-file: ', Failure.Message);
      ExitCode := ExitUsage;
    end;
  end;
end.
