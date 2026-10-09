{ SPDX-FileCopyrightText: 2026 Pascal Fairchild
  SPDX-License-Identifier: AGPL-3.0-only }

{ The plain-text record list: what write reads and what read prints. The grammar is in
  README.md. Write never judges a list: a duplicate name, a missing field or a length that
  lies are exactly the files the engine's tests need. }
unit RecordList;

{$mode objfpc}{$H+}{$R+}{$Q+}

interface

uses
  SysUtils, AesGcm;

const
  MagicLength = 8;
  { Magic, format version, key holder and sealed-key length: the header's fixed start. The
    sealed key follows it, then the nonce. }
  HeaderStartLength = MagicLength + 2 + 1 + 2;
  FormatVersion = 1;
  { The key file: no sealed key, so a list that names nothing writes the simplest file. }
  DefaultKeyHolder = 4;
  { A token that makes bytes (zeros:, random:) stops here: a typo of a few digits should
    fail, not fill the disk. Four times the format's whole-file limit is room enough for
    every oversized case. }
  GeneratedByteLimit = 4 * 65536;

type
  TEditKind = (EditTruncate, EditFlip, EditAppend);

  TFileEdit = record
    Kind: TEditKind;
    Offset: Int64;
    Data: TBytes;
  end;

  { Everything one list says about the file to write. }
  TFilePlan = record
    Magic: TBytes;
    Version: Word;
    KeyHolder: Byte;
    SealedKey: TBytes;
    { The 2-byte length written before the sealed key; given, it can lie. }
    SealedLengthGiven: Boolean;
    SealedLength: Word;
    NonceGiven: Boolean;
    Nonce: TNonce;
    Plaintext: TBytes;
    Edits: array of TFileEdit;
  end;

  ERecordList = class(Exception);

function ParseRecordList(const Text: string): TFilePlan;

{ Appends one record in the format's framing to Plaintext. }
procedure AppendRecord(var Plaintext: TBytes; const Name, Data: TBytes;
  NameLength: Word; DataLength: LongWord);

{ One token in the list's grammar that write reads back to the same bytes. }
function FormatValue(const Value: TBytes): string;

{ Strict UTF-8 as RFC 3629 has it: no overlong form, no surrogate, nothing past U+10FFFF. }
function IsValidUtf8(const Value: TBytes): Boolean;

procedure FillRandom(var Buffer; Count: SizeInt);

function BytesOf(const Text: string): TBytes;

implementation

{$IFDEF WINDOWS}
{ RtlGenRandom, exported by name as SystemFunction036. }
function SystemFunction036(Buffer: Pointer; Count: LongWord): ByteBool; stdcall;
  external 'advapi32.dll';
{$ENDIF}

procedure FillRandom(var Buffer; Count: SizeInt);
{$IFDEF UNIX}
var
  Source: File;
  ReadCount: LongInt;
{$ENDIF}
begin
  if Count = 0 then
    Exit;
  {$IFDEF UNIX}
  AssignFile(Source, '/dev/urandom');
  Reset(Source, 1);
  try
    BlockRead(Source, Buffer, Count, ReadCount);
    if ReadCount <> Count then
      raise ERecordList.Create('/dev/urandom gave too few bytes');
  finally
    CloseFile(Source);
  end;
  {$ELSE}
  {$IFDEF WINDOWS}
  if not SystemFunction036(@Buffer, Count) then
    raise ERecordList.Create('RtlGenRandom failed');
  {$ELSE}
  {$FATAL no random source for this platform}
  {$ENDIF}
  {$ENDIF}
end;

function BytesOf(const Text: string): TBytes;
begin
  Result := nil;
  SetLength(Result, Length(Text));
  if Length(Text) > 0 then
    Move(Text[1], Result[0], Length(Text));
end;

procedure AppendBytes(var Target: TBytes; const Source: TBytes);
var
  OldLength: SizeInt;
begin
  OldLength := Length(Target);
  SetLength(Target, OldLength + Length(Source));
  if Length(Source) > 0 then
    Move(Source[0], Target[OldLength], Length(Source));
end;

procedure AppendRecord(var Plaintext: TBytes; const Name, Data: TBytes;
  NameLength: Word; DataLength: LongWord);
var
  Framing: TBytes;
begin
  SetLength(Framing, 2);
  Framing[0] := Byte(NameLength shr 8);
  Framing[1] := Byte(NameLength and $FF);
  AppendBytes(Plaintext, Framing);
  AppendBytes(Plaintext, Name);
  SetLength(Framing, 4);
  Framing[0] := Byte(DataLength shr 24);
  Framing[1] := Byte((DataLength shr 16) and $FF);
  Framing[2] := Byte((DataLength shr 8) and $FF);
  Framing[3] := Byte(DataLength and $FF);
  AppendBytes(Plaintext, Framing);
  AppendBytes(Plaintext, Data);
end;

function IsValidUtf8(const Value: TBytes): Boolean;
var
  Index, ContinuationCount, Continuation: Integer;
  Lead, Lowest, Highest: Byte;
begin
  Index := 0;
  while Index < Length(Value) do
  begin
    Lead := Value[Index];
    Lowest := $80;
    Highest := $BF;
    case Lead of
      $00..$7F: ContinuationCount := 0;
      $C2..$DF: ContinuationCount := 1;
      $E0: begin ContinuationCount := 2; Lowest := $A0; end;
      $E1..$EC, $EE..$EF: ContinuationCount := 2;
      $ED: begin ContinuationCount := 2; Highest := $9F; end;
      $F0: begin ContinuationCount := 3; Lowest := $90; end;
      $F1..$F3: ContinuationCount := 3;
      $F4: begin ContinuationCount := 3; Highest := $8F; end;
    else
      Exit(False);
    end;
    if Index + ContinuationCount > High(Value) then
      Exit(False);
    for Continuation := 1 to ContinuationCount do
    begin
      { Only the first continuation byte has the narrowed range. }
      if Continuation > 1 then
      begin
        Lowest := $80;
        Highest := $BF;
      end;
      if (Value[Index + Continuation] < Lowest) or (Value[Index + Continuation] > Highest) then
        Exit(False);
    end;
    Inc(Index, ContinuationCount + 1);
  end;
  Result := True;
end;

function FormatValue(const Value: TBytes): string;
var
  Index: Integer;
  Printable: Boolean;
begin
  Printable := IsValidUtf8(Value);
  for Index := 0 to High(Value) do
    if (Value[Index] < $20) or (Value[Index] = $7F) then
      Printable := False;
  { The C1 controls, U+0080 to U+009F: in valid UTF-8 a $C2 is always a lead byte. }
  for Index := 0 to High(Value) - 1 do
    if (Value[Index] = $C2) and (Value[Index + 1] in [$80..$9F]) then
      Printable := False;
  if Printable then
  begin
    Result := '"';
    for Index := 0 to High(Value) do
    begin
      if (Value[Index] = Ord('"')) or (Value[Index] = Ord('\')) then
        Result := Result + '\';
      Result := Result + Chr(Value[Index]);
    end;
    Result := Result + '"';
  end
  else
  begin
    Result := 'hex:';
    for Index := 0 to High(Value) do
      Result := Result + LowerCase(IntToHex(Value[Index], 2));
  end;
end;

type
  TTokenKind = (TokenWord, TokenQuoted);

  TToken = record
    Kind: TTokenKind;
    Text: string;
  end;

  TTokenList = array of TToken;

function HexDigitValue(Character: Char; out Value: Integer): Boolean;
begin
  case Character of
    '0'..'9': Value := Ord(Character) - Ord('0');
    'a'..'f': Value := Ord(Character) - Ord('a') + 10;
    'A'..'F': Value := Ord(Character) - Ord('A') + 10;
  else
    Exit(False);
  end;
  Result := True;
end;

function SplitTokens(const Line: string; LineNumber: Integer): TTokenList;
var
  Position, HighValue, LowValue: Integer;
  Current: TToken;
begin
  Result := nil;
  Position := 1;
  while Position <= Length(Line) do
  begin
    if Line[Position] in [' ', #9] then
    begin
      Inc(Position);
      Continue;
    end;
    if Line[Position] = '#' then
      Break;
    if Line[Position] = '"' then
    begin
      Current.Kind := TokenQuoted;
      Current.Text := '';
      Inc(Position);
      while True do
      begin
        if Position > Length(Line) then
          raise ERecordList.CreateFmt('line %d: a quoted value is not closed', [LineNumber]);
        if Line[Position] = '"' then
          Break;
        if Line[Position] = '\' then
        begin
          Inc(Position);
          if Position > Length(Line) then
            raise ERecordList.CreateFmt('line %d: a quoted value ends in a backslash',
              [LineNumber]);
          case Line[Position] of
            '\', '"': Current.Text := Current.Text + Line[Position];
            'n': Current.Text := Current.Text + #10;
            'r': Current.Text := Current.Text + #13;
            't': Current.Text := Current.Text + #9;
            'x':
              begin
                if (Position + 2 > Length(Line))
                  or not HexDigitValue(Line[Position + 1], HighValue)
                  or not HexDigitValue(Line[Position + 2], LowValue) then
                  raise ERecordList.CreateFmt('line %d: \x needs two hex digits', [LineNumber]);
                Current.Text := Current.Text + Chr(HighValue * 16 + LowValue);
                Inc(Position, 2);
              end;
          else
            raise ERecordList.CreateFmt('line %d: unknown escape \%s',
              [LineNumber, Line[Position]]);
          end;
        end
        else
          Current.Text := Current.Text + Line[Position];
        Inc(Position);
      end;
      Inc(Position);
      if (Position <= Length(Line)) and not (Line[Position] in [' ', #9]) then
        raise ERecordList.CreateFmt('line %d: a quoted value runs into the next token',
          [LineNumber]);
    end
    else
    begin
      Current.Kind := TokenWord;
      Current.Text := '';
      while (Position <= Length(Line)) and not (Line[Position] in [' ', #9]) do
      begin
        Current.Text := Current.Text + Line[Position];
        Inc(Position);
      end;
    end;
    SetLength(Result, Length(Result) + 1);
    Result[High(Result)] := Current;
  end;
end;

function ParseNumber(const Text: string; Maximum: QWord; LineNumber: Integer): QWord;
var
  Index: Integer;
begin
  if (Text = '') or (Length(Text) > 20) then
    raise ERecordList.CreateFmt('line %d: "%s" is not a number', [LineNumber, Text]);
  Result := 0;
  for Index := 1 to Length(Text) do
  begin
    if not (Text[Index] in ['0'..'9']) then
      raise ERecordList.CreateFmt('line %d: "%s" is not a number', [LineNumber, Text]);
    if Result > (Maximum - (Ord(Text[Index]) - Ord('0'))) div 10 then
      raise ERecordList.CreateFmt('line %d: %s is more than %d', [LineNumber, Text, Maximum]);
    Result := Result * 10 + QWord(Ord(Text[Index]) - Ord('0'));
  end;
end;

function ParseValue(const Token: TToken; LineNumber: Integer): TBytes;
var
  Digits: string;
  Index, HighValue, LowValue: Integer;
  Count: QWord;
begin
  if Token.Kind = TokenQuoted then
    Exit(BytesOf(Token.Text));
  if Copy(Token.Text, 1, 4) = 'hex:' then
  begin
    Digits := Copy(Token.Text, 5, MaxInt);
    if Odd(Length(Digits)) then
      raise ERecordList.CreateFmt('line %d: hex: needs an even number of digits',
        [LineNumber]);
    SetLength(Result, Length(Digits) div 2);
    for Index := 0 to High(Result) do
    begin
      if not HexDigitValue(Digits[2 * Index + 1], HighValue)
        or not HexDigitValue(Digits[2 * Index + 2], LowValue) then
        raise ERecordList.CreateFmt('line %d: "%s" is not hex', [LineNumber, Digits]);
      Result[Index] := Byte(HighValue * 16 + LowValue);
    end;
    Exit;
  end;
  if Copy(Token.Text, 1, 6) = 'zeros:' then
  begin
    Count := ParseNumber(Copy(Token.Text, 7, MaxInt), GeneratedByteLimit, LineNumber);
    SetLength(Result, Count);
    if Count > 0 then
      FillChar(Result[0], Count, 0);
    Exit;
  end;
  if Copy(Token.Text, 1, 7) = 'random:' then
  begin
    Count := ParseNumber(Copy(Token.Text, 8, MaxInt), GeneratedByteLimit, LineNumber);
    SetLength(Result, Count);
    if Count > 0 then
      FillRandom(Result[0], Count);
    Exit;
  end;
  raise ERecordList.CreateFmt('line %d: "%s" is not a value: quote it, or use hex:, zeros: ' +
    'or random:', [LineNumber, Token.Text]);
end;

procedure RequireTokenCount(const Tokens: TTokenList; Lowest, Highest, LineNumber: Integer);
begin
  if (Length(Tokens) < Lowest) or (Length(Tokens) > Highest) then
    raise ERecordList.CreateFmt('line %d: %s takes %d to %d values, not %d',
      [LineNumber, Tokens[0].Text, Lowest - 1, Highest - 1, Length(Tokens) - 1]);
end;

procedure AddEdit(var Plan: TFilePlan; Kind: TEditKind; Offset: Int64; const Data: TBytes);
begin
  SetLength(Plan.Edits, Length(Plan.Edits) + 1);
  Plan.Edits[High(Plan.Edits)].Kind := Kind;
  Plan.Edits[High(Plan.Edits)].Offset := Offset;
  Plan.Edits[High(Plan.Edits)].Data := Data;
end;

procedure ParseRecordLine(var Plan: TFilePlan; const Tokens: TTokenList; LineNumber: Integer);
var
  Name, Data: TBytes;
  NameLength: QWord;
  DataLength: QWord;
  Index: Integer;
  Option: string;
begin
  RequireTokenCount(Tokens, 3, 5, LineNumber);
  Name := ParseValue(Tokens[1], LineNumber);
  Data := ParseValue(Tokens[2], LineNumber);
  NameLength := Length(Name);
  DataLength := Length(Data);
  for Index := 3 to High(Tokens) do
  begin
    Option := Tokens[Index].Text;
    if Tokens[Index].Kind <> TokenWord then
      raise ERecordList.CreateFmt('line %d: record takes a name and data, then options',
        [LineNumber]);
    if Copy(Option, 1, 12) = 'name-length=' then
      NameLength := ParseNumber(Copy(Option, 13, MaxInt), High(Word), LineNumber)
    else if Copy(Option, 1, 12) = 'data-length=' then
      DataLength := ParseNumber(Copy(Option, 13, MaxInt), High(LongWord), LineNumber)
    else
      raise ERecordList.CreateFmt('line %d: unknown option "%s"', [LineNumber, Option]);
  end;
  if NameLength > High(Word) then
    raise ERecordList.CreateFmt('line %d: a name of %d bytes does not fit its 2-byte length',
      [LineNumber, Length(Name)]);
  AppendRecord(Plan.Plaintext, Name, Data, Word(NameLength), LongWord(DataLength));
end;

function ParseRecordList(const Text: string): TFilePlan;
var
  Lines: TStringArray;
  LineIndex, Index: Integer;
  Line, Directive: string;
  Tokens: TTokenList;
  Value: TBytes;
begin
  Result.Magic := BytesOf('HADVBOOT');
  Result.Version := FormatVersion;
  Result.KeyHolder := DefaultKeyHolder;
  Result.SealedKey := nil;
  Result.SealedLengthGiven := False;
  Result.SealedLength := 0;
  Result.NonceGiven := False;
  FillChar(Result.Nonce, SizeOf(Result.Nonce), 0);
  Result.Plaintext := nil;
  Result.Edits := nil;
  Lines := Text.Split([#10]);
  for LineIndex := 0 to High(Lines) do
  begin
    Line := Lines[LineIndex];
    if (Line <> '') and (Line[Length(Line)] = #13) then
      SetLength(Line, Length(Line) - 1);
    Tokens := SplitTokens(Line, LineIndex + 1);
    if Length(Tokens) = 0 then
      Continue;
    if Tokens[0].Kind <> TokenWord then
      raise ERecordList.CreateFmt('line %d: a line must start with a directive, not a quoted value', [LineIndex + 1]);
    Directive := Tokens[0].Text;
    if Directive = 'record' then
      ParseRecordLine(Result, Tokens, LineIndex + 1)
    else if Directive = 'magic' then
    begin
      RequireTokenCount(Tokens, 2, 2, LineIndex + 1);
      Result.Magic := ParseValue(Tokens[1], LineIndex + 1);
      if Length(Result.Magic) <> MagicLength then
        raise ERecordList.CreateFmt('line %d: magic is %d bytes, not %d',
          [LineIndex + 1, Length(Result.Magic), MagicLength]);
    end
    else if Directive = 'version' then
    begin
      RequireTokenCount(Tokens, 2, 2, LineIndex + 1);
      Result.Version := Word(ParseNumber(Tokens[1].Text, High(Word), LineIndex + 1));
    end
    else if Directive = 'holder' then
    begin
      RequireTokenCount(Tokens, 2, 2, LineIndex + 1);
      Result.KeyHolder := Byte(ParseNumber(Tokens[1].Text, High(Byte), LineIndex + 1));
    end
    else if Directive = 'sealed' then
    begin
      { Several values are joined, so a Windows key's name and wrap fit on one line. }
      if Length(Tokens) < 2 then
        raise ERecordList.CreateFmt('line %d: sealed takes one value or more', [LineIndex + 1]);
      Result.SealedKey := nil;
      for Index := 1 to High(Tokens) do
        AppendBytes(Result.SealedKey, ParseValue(Tokens[Index], LineIndex + 1));
      if Length(Result.SealedKey) > GeneratedByteLimit then
        raise ERecordList.CreateFmt('line %d: the sealed key is more than %d bytes',
          [LineIndex + 1, GeneratedByteLimit]);
    end
    else if Directive = 'sealed-length' then
    begin
      RequireTokenCount(Tokens, 2, 2, LineIndex + 1);
      Result.SealedLength := Word(ParseNumber(Tokens[1].Text, High(Word), LineIndex + 1));
      Result.SealedLengthGiven := True;
    end
    else if Directive = 'nonce' then
    begin
      RequireTokenCount(Tokens, 2, 2, LineIndex + 1);
      Value := ParseValue(Tokens[1], LineIndex + 1);
      if Length(Value) <> NonceLength then
        raise ERecordList.CreateFmt('line %d: nonce is %d bytes, not %d',
          [LineIndex + 1, Length(Value), NonceLength]);
      Move(Value[0], Result.Nonce, NonceLength);
      Result.NonceGiven := True;
    end
    else if Directive = 'raw' then
    begin
      RequireTokenCount(Tokens, 2, 2, LineIndex + 1);
      AppendBytes(Result.Plaintext, ParseValue(Tokens[1], LineIndex + 1));
    end
    else if Directive = 'truncate' then
    begin
      RequireTokenCount(Tokens, 2, 2, LineIndex + 1);
      AddEdit(Result, EditTruncate,
        ParseNumber(Tokens[1].Text, High(LongWord), LineIndex + 1), nil);
    end
    else if Directive = 'flip' then
    begin
      RequireTokenCount(Tokens, 2, 2, LineIndex + 1);
      AddEdit(Result, EditFlip,
        ParseNumber(Tokens[1].Text, High(LongWord), LineIndex + 1), nil);
    end
    else if Directive = 'append' then
    begin
      RequireTokenCount(Tokens, 2, 2, LineIndex + 1);
      AddEdit(Result, EditAppend, 0, ParseValue(Tokens[1], LineIndex + 1));
    end
    else
      raise ERecordList.CreateFmt('line %d: unknown directive "%s"',
        [LineIndex + 1, Directive]);
  end;
end;

end.
