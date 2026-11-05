{ SPDX-FileCopyrightText: 2026 Pascal Fairchild
  SPDX-License-Identifier: AGPL-3.0-only }

{ The bootstrap file oracle: a second reader and writer of bootstrap file format 1, written
  from the format's description alone and never from the engine's code. Where the two
  disagree about a file, one of them misread the description. Usage is in README.md. }
program BootstrapFile;

{$mode objfpc}{$H+}{$R+}{$Q+}

uses
  SysUtils, Classes, AesGcm, EditList;

const
  WholeFileLimit = 65536;
  { What write seals and the edits list are ours; a bound keeps a wrong path from reading a
    disk image, with room for a plaintext that makes a file past the whole-file limit. }
  InputLimit = 4 * WholeFileLimit;
  { 44 characters and a carriage return and line feed. }
  KeyFileLimit = 46;
  KeyTextLength = 44;

  ExitUsage = 1;
  { The engine's refusals of a file: 2 is ErrFileTooLarge, 3 ErrHeader, 4 ErrUnseal. }
  ExitTooLarge = 2;
  ExitHeader = 3;
  ExitUnseal = 4;

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

function ReadInput(const Path: string): TBytes;
begin
  Result := ReadBounded(Path, InputLimit);
  if Length(Result) > InputLimit then
    raise EUsage.CreateFmt('%s: more than %d bytes', [Path, InputLimit]);
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

function TextOf(const Data: TBytes): string;
begin
  SetLength(Result, Length(Data));
  if Length(Data) > 0 then
    Move(Data[0], Result[1], Length(Data));
end;

{ The key file's form and nothing else: 43 characters of RFC 4648's standard alphabet, then
  its one padding character, decoding to 32 bytes with the 2 bits after the last byte zero;
  then nothing, one line feed, or one carriage return and line feed. A key of 32 zero bytes is
  taken: the oracle judges no key, the engine's tests do. }
function LoadKey(const Path: string): TAesKey;
const
  Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
var
  Raw: TBytes;
  Text: string;
  Index, Value, Bits, BitCount, Filled: Integer;
begin
  Raw := ReadBounded(Path, KeyFileLimit);
  Text := TextOf(Raw);
  if Length(Raw) > 0 then
    FillChar(Raw[0], Length(Raw), 0);
  if (Length(Text) = KeyTextLength + 2) and (Copy(Text, KeyTextLength + 1, 2) = #13#10) then
    SetLength(Text, KeyTextLength)
  else if (Length(Text) = KeyTextLength + 1) and (Text[KeyTextLength + 1] = #10) then
    SetLength(Text, KeyTextLength);
  if (Length(Text) <> KeyTextLength) or (Text[KeyTextLength] <> '=') then
    raise EUsage.CreateFmt('%s: not a key in the key file''s form', [Path]);
  Bits := 0;
  BitCount := 0;
  Filled := 0;
  for Index := 1 to KeyTextLength - 1 do
  begin
    Value := Pos(Text[Index], Alphabet) - 1;
    if Value < 0 then
      raise EUsage.CreateFmt('%s: not a key in the key file''s form', [Path]);
    Bits := ((Bits shl 6) or Value) and $FFFFFF;
    Inc(BitCount, 6);
    if BitCount >= 8 then
    begin
      Dec(BitCount, 8);
      Result[Filled] := Byte((Bits shr BitCount) and $FF);
      Inc(Filled);
    end;
  end;
  { 43 characters carry 258 bits: the key's 256, then 2 that must be zero. }
  if (Filled <> KeyLength) or (BitCount <> 2) or ((Bits and 3) <> 0) then
    raise EUsage.CreateFmt('%s: not a key in the key file''s form', [Path]);
  FillChar(Text[1], Length(Text), 0);
end;

function SealPlan(const Key: TAesKey; const Plan: TFilePlan; const Plaintext: TBytes): TBytes;
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
  else
    SealedLength := Length(Plan.SealedKey);
  { The header, then the nonce: every byte before the sealed plaintext. }
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
  { The additional data is every byte before the sealed plaintext as written, a wrong header
    included, so a file with a bad header still carries a tag that verifies. }
  Sealed := Seal(Key, Nonce, Header, Plaintext);
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

procedure RunWrite(const KeyPath, PlaintextPath, OutputPath, EditsPath: string);
var
  Key: TAesKey;
  Plaintext: TBytes;
  Plan: TFilePlan;
begin
  if EditsPath = '' then
    Plan := DefaultPlan
  else
    Plan := ParseEditList(TextOf(ReadInput(EditsPath)));
  Plaintext := ReadInput(PlaintextPath);
  Key := LoadKey(KeyPath);
  try
    WriteWhole(OutputPath, SealPlan(Key, Plan, Plaintext));
  finally
    FillChar(Key, SizeOf(Key), 0);
  end;
end;

function ReadNumber(const Data: TBytes; Offset, Width: Integer): LongWord;
var
  Index: Integer;
begin
  Result := 0;
  for Index := 0 to Width - 1 do
    Result := (Result shl 8) or Data[Offset + Index];
end;

{ The whole file's size, then its header against format version 1 for the key file. Every
  refusal here comes before the key file is read. }
procedure CheckHeader(const Whole: TBytes);
begin
  if Length(Whole) > WholeFileLimit then
    raise ERefusal.CreateRefusal(ExitTooLarge,
      Format('the file is larger than %d bytes', [WholeFileLimit]));
  if Length(Whole) < HeaderStartLength + NonceLength + TagLength then
    raise ERefusal.CreateRefusal(ExitHeader, Format(
      'the file is %d bytes, shorter than its header, nonce and tag', [Length(Whole)]));
  if TextOf(Copy(Whole, 0, MagicLength)) <> 'HADVBOOT' then
    raise ERefusal.CreateRefusal(ExitHeader, 'the file does not begin with HADVBOOT');
  if ReadNumber(Whole, MagicLength, 2) <> FormatVersion then
    raise ERefusal.CreateRefusal(ExitHeader, Format(
      'the format version is %d; this oracle reads version 1',
      [ReadNumber(Whole, MagicLength, 2)]));
  if Whole[MagicLength + 2] <> KeyHolderKeyFile then
    raise ERefusal.CreateRefusal(ExitHeader, Format(
      'the key holder is %d; this oracle reads 1, the key file', [Whole[MagicLength + 2]]));
  if ReadNumber(Whole, MagicLength + 3, 2) <> 0 then
    raise ERefusal.CreateRefusal(ExitHeader, Format(
      'the sealed key is %d bytes; the key file has none', [ReadNumber(Whole, MagicLength + 3, 2)]));
end;

procedure RunRead(const KeyPath, FilePath: string);
var
  Key: TAesKey;
  Whole, Authenticated, Sealed, Plaintext: TBytes;
  Nonce: TNonce;
begin
  { The header's verdict comes before the key file is even read, as the engine's does. }
  Whole := ReadBounded(FilePath, WholeFileLimit);
  CheckHeader(Whole);
  Authenticated := Copy(Whole, 0, HeaderStartLength + NonceLength);
  Move(Whole[HeaderStartLength], Nonce, NonceLength);
  Sealed := Copy(Whole, HeaderStartLength + NonceLength, MaxInt);
  Key := LoadKey(KeyPath);
  try
    if not Open(Key, Nonce, Authenticated, Sealed, Plaintext) then
      raise ERefusal.CreateRefusal(ExitUnseal, 'the GCM tag does not verify');
  finally
    FillChar(Key, SizeOf(Key), 0);
  end;
  WriteWhole('-', Plaintext);
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
  WriteLn(StdErr, 'usage: bootstrap-file write KEY PLAINTEXT OUTPUT [EDITS]');
  WriteLn(StdErr, '       bootstrap-file read KEY FILE');
  WriteLn(StdErr, '       bootstrap-file newkey OUTPUT');
  WriteLn(StdErr, '       bootstrap-file selftest');
  WriteLn(StdErr, 'Any path may be - for standard input or output. See README.md.');
end;

begin
  try
    if ((ParamCount = 4) or (ParamCount = 5)) and (ParamStr(1) = 'write') then
      RunWrite(ParamStr(2), ParamStr(3), ParamStr(4), ParamStr(5))
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
