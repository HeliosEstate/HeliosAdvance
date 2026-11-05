{ SPDX-FileCopyrightText: 2026 Pascal Fairchild
  SPDX-License-Identifier: AGPL-3.0-only }

{ AES-256 and GCM with a 96-bit nonce, written from FIPS-197 and NIST SP 800-38D. The oracle
  carries its own cipher so that nothing it shares with the engine is code: the engine uses
  its language's library, and the published vectors in Selftest bind both to the standard.
  Speed does not matter; a bootstrap file is at most 64 KiB, so GHASH is the bit-at-a-time
  multiplication from the standard, which is easy to check by reading. }
unit AesGcm;

{$mode objfpc}{$H+}{$R+}{$Q+}

interface

uses
  SysUtils;

const
  KeyLength = 32;
  NonceLength = 12;
  TagLength = 16;

type
  TAesKey = array[0..KeyLength - 1] of Byte;
  TNonce = array[0..NonceLength - 1] of Byte;
  TBlock = array[0..15] of Byte;

{ Ciphertext followed by the tag. }
function Seal(const Key: TAesKey; const Nonce: TNonce;
  const AdditionalData, Plaintext: TBytes): TBytes;

{ False, with Plaintext empty, when the tag does not verify. Sealed is ciphertext then tag. }
function Open(const Key: TAesKey; const Nonce: TNonce;
  const AdditionalData, Sealed: TBytes; out Plaintext: TBytes): Boolean;

{ The block cipher alone, for the FIPS-197 vector. }
procedure EncryptBlock(const Key: TAesKey; const Input: TBlock; out Output: TBlock);

implementation

const
  RoundCount = 14;
  { 4 * (RoundCount + 1) words of four bytes. }
  ExpandedKeyLength = 240;

type
  TExpandedKey = array[0..ExpandedKeyLength - 1] of Byte;

var
  SubstitutionBox: array[0..255] of Byte;

{ Multiplication by x in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1. }
function MultiplyByX(Value: Byte): Byte;
begin
  if (Value and $80) <> 0 then
    Result := Byte(((Value shl 1) and $FF) xor $1B)
  else
    Result := Byte((Value shl 1) and $FF);
end;

function MultiplyField(Left, Right: Byte): Byte;
var
  Product: Byte;
begin
  Product := 0;
  while Right <> 0 do
  begin
    if (Right and 1) <> 0 then
      Product := Product xor Left;
    Left := MultiplyByX(Left);
    Right := Right shr 1;
  end;
  Result := Product;
end;

{ The S-box is derived, not typed in: a mistyped constant among 256 would pass every test
  that happens not to touch it. Inverse, then the affine map with constant $63. }
procedure BuildSubstitutionBox;
var
  Value, Inverse, Candidate, Affine: Integer;
  Rotated: Byte;
  Shift: Integer;
begin
  for Value := 0 to 255 do
  begin
    Inverse := 0;
    if Value <> 0 then
      for Candidate := 1 to 255 do
        if MultiplyField(Byte(Value), Byte(Candidate)) = 1 then
        begin
          Inverse := Candidate;
          Break;
        end;
    Affine := Inverse;
    for Shift := 1 to 4 do
    begin
      Rotated := Byte(((Inverse shl Shift) or (Inverse shr (8 - Shift))) and $FF);
      Affine := Affine xor Rotated;
    end;
    SubstitutionBox[Value] := Byte(Affine xor $63);
  end;
end;

procedure ExpandKey(const Key: TAesKey; out Expanded: TExpandedKey);
var
  WordIndex, ByteIndex: Integer;
  Temporary: array[0..3] of Byte;
  RotatedFirst: Byte;
  RoundConstant: Byte;
begin
  Move(Key, Expanded, KeyLength);
  RoundConstant := 1;
  for WordIndex := 8 to 59 do
  begin
    for ByteIndex := 0 to 3 do
      Temporary[ByteIndex] := Expanded[(WordIndex - 1) * 4 + ByteIndex];
    if WordIndex mod 8 = 0 then
    begin
      RotatedFirst := Temporary[0];
      Temporary[0] := SubstitutionBox[Temporary[1]] xor RoundConstant;
      Temporary[1] := SubstitutionBox[Temporary[2]];
      Temporary[2] := SubstitutionBox[Temporary[3]];
      Temporary[3] := SubstitutionBox[RotatedFirst];
      RoundConstant := MultiplyByX(RoundConstant);
    end
    else if WordIndex mod 8 = 4 then
      for ByteIndex := 0 to 3 do
        Temporary[ByteIndex] := SubstitutionBox[Temporary[ByteIndex]];
    for ByteIndex := 0 to 3 do
      Expanded[WordIndex * 4 + ByteIndex] :=
        Expanded[(WordIndex - 8) * 4 + ByteIndex] xor Temporary[ByteIndex];
  end;
end;

{ The state is column-major, byte Row + 4 * Column, which is also the order of the input
  block and of the round key's bytes, so AddRoundKey is a plain byte-wise xor. }
procedure EncryptWithExpandedKey(const Expanded: TExpandedKey; const Input: TBlock;
  out Output: TBlock);
var
  State, Shifted: TBlock;
  Round, Index, Row, Column: Integer;
  First, Second, Third, Fourth: Byte;
begin
  for Index := 0 to 15 do
    State[Index] := Input[Index] xor Expanded[Index];
  for Round := 1 to RoundCount do
  begin
    for Index := 0 to 15 do
      State[Index] := SubstitutionBox[State[Index]];
    for Row := 0 to 3 do
      for Column := 0 to 3 do
        Shifted[Row + 4 * Column] := State[Row + 4 * ((Column + Row) mod 4)];
    State := Shifted;
    if Round <> RoundCount then
      for Column := 0 to 3 do
      begin
        First := State[4 * Column];
        Second := State[4 * Column + 1];
        Third := State[4 * Column + 2];
        Fourth := State[4 * Column + 3];
        State[4 * Column] := MultiplyByX(First) xor MultiplyByX(Second) xor Second
          xor Third xor Fourth;
        State[4 * Column + 1] := First xor MultiplyByX(Second) xor MultiplyByX(Third)
          xor Third xor Fourth;
        State[4 * Column + 2] := First xor Second xor MultiplyByX(Third)
          xor MultiplyByX(Fourth) xor Fourth;
        State[4 * Column + 3] := MultiplyByX(First) xor First xor Second xor Third
          xor MultiplyByX(Fourth);
      end;
    for Index := 0 to 15 do
      State[Index] := State[Index] xor Expanded[16 * Round + Index];
  end;
  Output := State;
end;

procedure EncryptBlock(const Key: TAesKey; const Input: TBlock; out Output: TBlock);
var
  Expanded: TExpandedKey;
begin
  ExpandKey(Key, Expanded);
  EncryptWithExpandedKey(Expanded, Input, Output);
  FillChar(Expanded, SizeOf(Expanded), 0);
end;

{ SP 800-38D's Algorithm 1. Bit 0 is the most significant bit of byte 0; R is $E1 then
  fifteen zero bytes. }
procedure MultiplyGalois(const Left, Right: TBlock; out Product: TBlock);
var
  Accumulator, Shifting: TBlock;
  BitIndex, Index: Integer;
  LowBitSet: Boolean;
begin
  FillChar(Accumulator, SizeOf(Accumulator), 0);
  Shifting := Right;
  for BitIndex := 0 to 127 do
  begin
    if (Left[BitIndex div 8] and ($80 shr (BitIndex mod 8))) <> 0 then
      for Index := 0 to 15 do
        Accumulator[Index] := Accumulator[Index] xor Shifting[Index];
    LowBitSet := (Shifting[15] and 1) <> 0;
    for Index := 15 downto 1 do
      Shifting[Index] := Byte((Shifting[Index] shr 1) or ((Shifting[Index - 1] and 1) shl 7));
    Shifting[0] := Shifting[0] shr 1;
    if LowBitSet then
      Shifting[0] := Shifting[0] xor $E1;
  end;
  Product := Accumulator;
end;

{ Absorbs Data into the running hash, zero-padded to a whole number of blocks. }
procedure AbsorbPadded(const HashKey: TBlock; var Hash: TBlock; const Data: TBytes);
var
  Offset, Index: Integer;
  Block: TBlock;
begin
  Offset := 0;
  while Offset < Length(Data) do
  begin
    FillChar(Block, SizeOf(Block), 0);
    for Index := 0 to 15 do
      if Offset + Index < Length(Data) then
        Block[Index] := Data[Offset + Index];
    for Index := 0 to 15 do
      Hash[Index] := Hash[Index] xor Block[Index];
    MultiplyGalois(Hash, HashKey, Hash);
    Inc(Offset, 16);
  end;
end;

procedure StoreBitLength(var Block: TBlock; Offset: Integer; ByteCount: Int64);
var
  BitCount: QWord;
  Index: Integer;
begin
  BitCount := QWord(ByteCount) * 8;
  for Index := 7 downto 0 do
  begin
    Block[Offset + Index] := Byte(BitCount and $FF);
    BitCount := BitCount shr 8;
  end;
end;

function ComputeTag(const Expanded: TExpandedKey; const InitialCounter: TBlock;
  const AdditionalData, Ciphertext: TBytes): TBlock;
var
  HashKey, Hash, LengthBlock, Zero, Mask: TBlock;
  Index: Integer;
begin
  FillChar(Zero, SizeOf(Zero), 0);
  EncryptWithExpandedKey(Expanded, Zero, HashKey);
  FillChar(Hash, SizeOf(Hash), 0);
  AbsorbPadded(HashKey, Hash, AdditionalData);
  AbsorbPadded(HashKey, Hash, Ciphertext);
  StoreBitLength(LengthBlock, 0, Length(AdditionalData));
  StoreBitLength(LengthBlock, 8, Length(Ciphertext));
  for Index := 0 to 15 do
    Hash[Index] := Hash[Index] xor LengthBlock[Index];
  MultiplyGalois(Hash, HashKey, Hash);
  EncryptWithExpandedKey(Expanded, InitialCounter, Mask);
  for Index := 0 to 15 do
    Result[Index] := Hash[Index] xor Mask[Index];
end;

{ With a 96-bit nonce the first counter block is the nonce then 00 00 00 01; the payload's
  counter starts one past it, incrementing only the low 32 bits. }
procedure FormInitialCounter(const Nonce: TNonce; out Counter: TBlock);
begin
  Move(Nonce, Counter, NonceLength);
  Counter[12] := 0;
  Counter[13] := 0;
  Counter[14] := 0;
  Counter[15] := 1;
end;

procedure IncrementCounter(var Counter: TBlock);
var
  Index: Integer;
begin
  for Index := 15 downto 12 do
  begin
    if Counter[Index] <> $FF then
    begin
      Counter[Index] := Counter[Index] + 1;
      Exit;
    end;
    Counter[Index] := 0;
  end;
end;

function ApplyCounterMode(const Expanded: TExpandedKey; const InitialCounter: TBlock;
  const Input: TBytes): TBytes;
var
  Counter, Keystream: TBlock;
  Offset, Index: Integer;
begin
  Result := nil;
  SetLength(Result, Length(Input));
  Counter := InitialCounter;
  Offset := 0;
  while Offset < Length(Input) do
  begin
    IncrementCounter(Counter);
    EncryptWithExpandedKey(Expanded, Counter, Keystream);
    for Index := 0 to 15 do
      if Offset + Index < Length(Input) then
        Result[Offset + Index] := Input[Offset + Index] xor Keystream[Index];
    Inc(Offset, 16);
  end;
end;

function Seal(const Key: TAesKey; const Nonce: TNonce;
  const AdditionalData, Plaintext: TBytes): TBytes;
var
  Expanded: TExpandedKey;
  InitialCounter, Tag: TBlock;
  Ciphertext: TBytes;
begin
  ExpandKey(Key, Expanded);
  FormInitialCounter(Nonce, InitialCounter);
  Ciphertext := ApplyCounterMode(Expanded, InitialCounter, Plaintext);
  Tag := ComputeTag(Expanded, InitialCounter, AdditionalData, Ciphertext);
  FillChar(Expanded, SizeOf(Expanded), 0);
  Result := nil;
  SetLength(Result, Length(Ciphertext) + TagLength);
  if Length(Ciphertext) > 0 then
    Move(Ciphertext[0], Result[0], Length(Ciphertext));
  Move(Tag, Result[Length(Ciphertext)], TagLength);
end;

function Open(const Key: TAesKey; const Nonce: TNonce;
  const AdditionalData, Sealed: TBytes; out Plaintext: TBytes): Boolean;
var
  Expanded: TExpandedKey;
  InitialCounter, Expected: TBlock;
  Ciphertext: TBytes;
  Difference: Byte;
  Index: Integer;
begin
  Plaintext := nil;
  if Length(Sealed) < TagLength then
    Exit(False);
  Ciphertext := Copy(Sealed, 0, Length(Sealed) - TagLength);
  ExpandKey(Key, Expanded);
  FormInitialCounter(Nonce, InitialCounter);
  Expected := ComputeTag(Expanded, InitialCounter, AdditionalData, Ciphertext);
  Difference := 0;
  for Index := 0 to TagLength - 1 do
    Difference := Difference or (Expected[Index] xor Sealed[Length(Ciphertext) + Index]);
  if Difference = 0 then
    Plaintext := ApplyCounterMode(Expanded, InitialCounter, Ciphertext);
  FillChar(Expanded, SizeOf(Expanded), 0);
  Result := Difference = 0;
end;

initialization
  BuildSubstitutionBox;
end.
