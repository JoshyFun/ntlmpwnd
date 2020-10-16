program ntlmpwnd;

{$mode objfpc}{$H+}

uses
  Classes, SysUtils, CustApp, md5
  , utextstreamfilter
  ;

{.$DEFINE VERIFY_SORT}
{$DEFINE USE_INLINE}

type
  TNTLM=array [0..15] of BYTE;

  TNTLMHash=packed record
    NTLM: TNTLM;
    Repeats: uint32;
  end;
  TNTLMHashArray=packed array of TNTLMHash;

  TNTLMUsersHash=packed record
    NTML: TNTLM;
    User: array [0..255] of char;
  end;

type

  { Tntlmpwnd }

  Tntlmpwnd = class(TCustomApplication)
  protected
    INPUTFILE: string;
    HASHESPATH: string;
    USERSFILE: string;
    BLOCKS_BITS: integer;
    BLOCKS_BITS_MASK: integer;
    BLOCKS: integer;
    KEEP_INTERMEDIATE: Boolean;
    GenerateBlocks: Boolean;
    CheckUsers: Boolean;
    function GetHexIndex(apChar: pChar): integer;
    procedure DoRun; override;
    procedure NTLMPwndGen(var lTick: QWord);
    procedure SortBlocks(var lTick: QWord);
    procedure VerifySortedFiles();
    procedure CheckUsersProc();
    procedure CheckOnePassword(const aPassword: string);
  public
    constructor Create(TheOwner: TComponent); override;
    destructor Destroy; override;
    procedure WriteBanner; virtual;
    procedure WriteHelp; virtual;
    procedure WriteLongHelp; virtual;
    function  GetNTLMHashForPassword(const aPassword: string; out aWarning: Boolean): string;
  end;

  procedure QuickSort(const Arr: PBYTE; const ALow, AHigh: SizeInt; Stride: LongInt; const SwapBuffer: PBYTE); forward;

var
  HEXTABLE: array [char] of BYTE;


constructor Tntlmpwnd.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
  StopOnException:=True;

  INPUTFILE:='';
  HASHESPATH:='.'+PathDelim;
  BLOCKS_BITS:=5;
  BLOCKS_BITS_MASK:=(1 shl BLOCKS_BITS)-1;
  BLOCKS:=1 shl BLOCKS_BITS;
  KEEP_INTERMEDIATE:=false;
  GenerateBlocks:=false;
  CheckUsers:=false;
end;

destructor Tntlmpwnd.Destroy;
begin
  inherited Destroy;
end;

procedure Tntlmpwnd.WriteBanner;
begin
  writeln('NTLM hashes PWND check. (c) 2020 joshyfun@gmail.com. License LGPL.');
  writeln;
end;

procedure Tntlmpwnd.WriteHelp;
begin
  WriteBanner;
  writeln('Usage: ', ExtractFileName(ExeName), ' -h --help --generate-blocks --check-users [--bits={n}] [--hashes-path={path}]');
  writeln;
  writeln('-h --help               Show this help page (help a bit longer).');
  writeln('--generate-blocks       Generate blocks of PWND hashes.');
  writeln('  --pwndlist={file}     List of PWND hashes.');
  writeln('--check-users           Generate blocks of PWND hashes.');
  writeln('  --userslist={file}    List of user names:hashes.');
  writeln('--check-password={pass} Check one password against the pwndlist.');
  writeln('--bits                  Bits used to split the PWND list and reduce memory,');
  writeln('                        by default 5 bits, so 32 slices.');
  writeln('--hashes-path={path}    Where hashes post-processed will be stored or loaded,');
  writeln('                        stored when "--generate-blocks" and loaded for "check-users".');
  writeln('--get-ntlm-hash={pass}  Calculate the NTLM password hash.');
  writeln;
end;

procedure Tntlmpwnd.WriteLongHelp;
begin
  writeln('pwndlist file format:');
  writeln;
  writeln('0123456789ABCDEF0123456789ABCDEF:nnnnn');
  writeln;
  writeln('Where "0123456789ABCDEF0123456789ABCDEF" is NTLM hash in hexadecimal');
  writeln('and "nnnnn" is a number related with the hash.');
  writeln;
  writeln('userlist file format.');
  writeln;
  writeln('john.doe:0123456789ABCDEF0123456789ABCDEF');
  writeln;
  writeln('Where "john.doe" is the user name (":" is prohibited)');
  writeln('and "0123456789ABCDEF0123456789ABCDEF" is the user''s NTLM hash in hexadecimal.');
  writeln;
end;

function Tntlmpwnd.GetNTLMHashForPassword(const aPassword: string; out aWarning: Boolean): string;
var
  MD4D: TMD4Digest;
  w: array [1..28] of Char;
  lLimit, j: integer;
begin
  aWarning:=false;
  lLimit:=Length(aPassword);
  w[1]:=#0; // Avoid warning non initialized
  if lLimit>14 then lLimit:=14;
  for j := 1 to lLimit do begin
    w[j*2-1]:=aPassword[j];
    w[j*2]:=#0;
    if aPassword[j]>#127 then begin
      // Password uses non-ascii char, over 127 so it should
      // be converted to Unicode UTF-16le, but for simplicity
      // here it is not done and a Warning is issued.
      aWarning:=true;
    end;
  end;
  MD4D:=MD4Buffer(w[1],lLimit*2);
  Result:=MD4Print(MD4D);
end;

function StrToIntPchar(const aStr: pchar; const aMaxLength: integer): integer; {$IFDEF USE_INLINE} inline;{$ENDIF}
const
  MULTIPLIERS: array [0..9] of integer = (
  1,10,100,1000,10000,100000,1000000,10000000,100000000,1000000000
  );
var
  j: Integer;
  lStrLen: integer=0;
  lMulti: integer;
begin
  for j := 0 to Pred(aMaxLength) do begin
    if (aStr+j)^ in ['0'..'9'] then begin
      inc(lStrLen);
    end else begin
      break;
    end;
  end;
  Result:=0;
  lMulti:=0;
  while lStrLen>0 do begin
    dec(lStrLen);
    Result:=Result+(ord((aStr+lStrLen)^)-ord('0'))*MULTIPLIERS[lMulti];
    inc(lMulti);
  end;
end;

procedure InitializeHexTable();
begin
  FillChar(HEXTABLE[#0],sizeof(HEXTABLE),255);
  HEXTABLE['0']:=0;
  HEXTABLE['1']:=1;
  HEXTABLE['2']:=2;
  HEXTABLE['3']:=3;
  HEXTABLE['4']:=4;
  HEXTABLE['5']:=5;
  HEXTABLE['6']:=6;
  HEXTABLE['7']:=7;
  HEXTABLE['8']:=8;
  HEXTABLE['9']:=9;
  HEXTABLE['A']:=10;
  HEXTABLE['B']:=11;
  HEXTABLE['C']:=12;
  HEXTABLE['D']:=13;
  HEXTABLE['E']:=14;
  HEXTABLE['F']:=15;
  HEXTABLE['a']:=10;
  HEXTABLE['b']:=11;
  HEXTABLE['c']:=12;
  HEXTABLE['d']:=13;
  HEXTABLE['e']:=14;
  HEXTABLE['f']:=15;
end;

function fastHexToBin(HexValue, BinValue: PChar; BinBufSize: Integer): Integer; {$IFDEF USE_INLINE} inline;{$ENDIF}
var
  i,h,l : integer;
begin
  i:=binbufsize;
  while (i>0) do begin
    h:=HEXTABLE[HexValue^];
    inc(HexValue);
    l:=HEXTABLE[HexValue^];
    inc(HexValue);
    if (l=255) or (h=255) then begin
      Raise Exception.Create('Hexadecimal format damaged: '+HexValue);
    end;
    BinValue^:=char((h shl 4) or l);
    inc(BinValue);
    dec(i);
  end;
  result:=binbufsize-i;
end;

procedure ConvertHexToBin(constref TheLine: string; var TheHash: TNTLMHash); {$IFDEF USE_INLINE} inline;{$ENDIF}
begin
  fastHexToBin(@TheLine[1],@TheHash.NTLM[0],sizeof(TNTLMHash.NTLM));
  {$IFDEF FPC_BIG_ENDIAN}
  TheHash.Repeats:=NtoLE(StrToIntPchar(@TheLine[34],10));
  {$ELSE}
  TheHash.Repeats:=StrToIntPchar(@TheLine[34],10);
  {$ENDIF}
end;

function Tntlmpwnd.GetHexIndex(apChar: pChar): integer; {$IFDEF USE_INLINE} inline;{$ENDIF}
var
  lBits: integer;
  V: integer;
begin
  lBits:=BLOCKS_BITS;
  Result:=0;
  while lBits>0 do begin
    V:=HEXTABLE[apChar^];
    if V>15 then begin
      Raise exception.Create('Something went wrong, GexHexIndex.');
    end;
    if lBits>=4 then begin
      Result:=(Result shl 4) or V;
    end else begin
      Result:=(Result shl lBits) or (V shr (4-lBits)) ;
      break;
    end;
    inc(apChar);
    dec(lBits,4);
  end;
  Result:=Result and BLOCKS_BITS_MASK;
end;

function CompareNTLMHash(const d1,d2: PBYTE): integer;{$IFDEF USE_INLINE} inline;{$ENDIF}
var
  j: integer;
  B1,B2: integer;
begin
  for j := 0 to 15 do begin
    B1:=(d1+j)^;
    B2:=(d2+j)^;
    Result:=B1-B2;
    if Result<>0 then exit;
  end;
end;

function QuickSearch(const Arr: PBYTE; idxL,idxH: integer; Stride: Integer; Key: PBYTE): integer;
{.$DEFINE OPT_LINEAR_SEARCH}
var
  mi    : Integer;
  ms    : Integer;
  pb    : PByte absolute Arr;
  c     : integer;
  {$IFDEF OPT_LINEAR_SEARCH}
  j     : integer;
  {$ENDIF}
begin
  if idxH-idxL<=1 then begin
    if CompareNTLMHash(pb+(idxL*Stride) , Key)<>0 then begin
      if CompareNTLMHash(pb+(idxH*Stride) , Key)<>0 then begin
        Result:=-1;
      end else begin
        Result:=idxH;
      end;
    end else begin
      Result:=idxL;
    end;
    exit;
  end;
  mi:=(idxL+idxH) div 2;
  ms:=mi*Stride;
  c:=CompareNTLMHash(pb+ms , Key);
  if c > 0 then begin
    {$IFDEF OPT_LINEAR_SEARCH}
    if (mi-1)-idXL<250 then begin
      // Linear search
      for j := idxL to Pred(mi) do begin
        c:=CompareNTLMHash(pb+(j)*Stride , Key);
        if c>=0 then begin
          if c=0 then begin
            result:=j;
            exit;
          end else begin
            Result:=-1;
            exit;
          end;
        end;
      end;
      Result:=-1;
      exit;
    end;
    {$ENDIF}
    Result:=QuickSearch(Arr,idXL,mi-1,Stride,Key);
  end else if c < 0 then begin
    {$IFDEF OPT_LINEAR_SEARCH}
    if (idXH-(mi+1))<250 then begin
      // Linear search
      for j := mi+1 to idxH do begin
        c:=CompareNTLMHash(pb+(j)*Stride , Key);
        if c>=0 then begin
          if c=0 then begin
            result:=j;
            exit;
          end else begin
            Result:=-1;
            exit;
          end;
        end;
      end;
      Result:=-1;
      exit;
    end;
    {$ENDIF}
    Result:=QuickSearch(Arr,mi+1,idxH,Stride,Key);
  end else begin
    Result:=mi;
  end;
end;

procedure SortArray(const Arr: PBYTE; Count: Integer; Stride: Integer);
var
  buf: array of byte;
begin
  SetLength(buf, Stride);
  QuickSort(Arr, 0, Count-1, Stride, @buf[0]);
end;

procedure Tntlmpwnd.NTLMPwndGen(var lTick: QWord);
const
//  BUFFER_ENTRIES=1;
//  BUFFER_ENTRIES=(256*1024) div sizeof(TNTLMHash);
  BUFFER_ENTRIES=20000;
var
  lBlocks: array of TFileStream;
  lBlocksBuffers: array of TNTLMHashArray;
  lBlocksBufferCounter: array of integer;
  lTextFilter: TTextStreamFilter=nil;
  j, lIndex: Integer;
  TheLine: string;
  lEvery: integer=0;
  lCount: integer=0;
  lElapsed: QWord;
//  lSwap: TNTLMHash;
  procedure UpdateStatus;
  begin
    write(format('Round 1: %.2f%%',[(lTextFilter.Position / lTextFilter.Size)*100]),
          ' Elapsed: ',
          format('%.1n s',[lElapsed / 1000]),
          ' ',
          format('// Speed: %.1n h/s // Hashes: %.0n  ',[lCount / (lElapsed / 1000),double(lCount)]),#13);
  end;

begin
  SetLength(lBlocks,BLOCKS);
  SetLength(lBlocksBuffers,BLOCKS);
  SetLength(lBlocksBufferCounter,BLOCKS);
  // First split the original list of hashes using the defined first bits, each added bit
  // doubles the amount of files. Also conver the hexadecimal formato to binary format
  // 16 bytes instead 32 and add a 32 bits counter for repetitions.

  for j := Low(lBlocks) to High(lBlocks) do begin
    lBlocks[j]:=TFileStream.Create(ConcatPaths([HASHESPATH,format('ntlmblock-%.4d.bin',[j])]),fmCreate or fmShareDenyWrite);
  end;
  for j := Low(lBlocksBuffers) to High(lBlocksBuffers) do begin
    SetLength(lBlocksBuffers[j],BUFFER_ENTRIES);
    lBlocksBufferCounter[j]:=0;
  end;
  try
    lTextFilter:=TTextStreamFilter.Create(TFileStream.Create(INPUTFILE,fmOpenRead or fmShareDenyWrite));
    try
      while lTextFilter.ReadLn(TheLine) do begin
        if Length(TheLine)>0 then begin
          lIndex:=GetHexIndex(@TheLine[1]);
          ConvertHEXToBin(TheLine,lBlocksBuffers[lIndex][lBlocksBufferCounter[lIndex]]);
          lBlocksBufferCounter[lIndex]:=lBlocksBufferCounter[lIndex]+1;
          inc(lCount);
          if lBlocksBufferCounter[lIndex]=BUFFER_ENTRIES then begin
//            QuickSort(@lBlocksBuffers[lIndex][0],0,lBlocksBufferCounter[lIndex]-1,sizeof(TNTLMHash),@lSwap);
            // Flush buffer
            lBlocks[lIndex].Write(lBlocksBuffers[lIndex][0],lBlocksBufferCounter[lIndex]*Sizeof(TNTLMHash));
            lBlocksBufferCounter[lIndex]:=0;
            inc(lEvery);
          end;
        end;
        if lEvery>=BLOCKS then begin
          lElapsed:=GetTickCount64-lTick;
          UpdateStatus;
          lEvery:=0;
        end;
      end;
      UpdateStatus;
      for j := Low(lBlocksBuffers) to High(lBlocksBuffers) do begin
        if lBlocksBufferCounter[j]>0 then begin
//          QuickSort(@lBlocksBuffers[j][0],0,lBlocksBufferCounter[j]-1,sizeof(TNTLMHash),@lSwap);
          // Flush buffer
          lBlocks[j].Write(lBlocksBuffers[j][0],lBlocksBufferCounter[j]*Sizeof(TNTLMHash));
        end;
        lBlocksBufferCounter[j]:=0;
        SetLength(lBlocksBuffers[j],0);
      end;
    finally
      FreeAndNil(lTextFilter);
    end;
  finally
    for j := Low(lBlocks) to High(lBlocks) do begin
      lBlocks[j].Free;
    end;
    writeln;
  end;
end;

(*
procedure CopyMemory(const Source: PBYTE; const Dest: PBYTE;const Count: integer); {$IFDEF USE_INLINE} inline;{$ENDIF}
var
  j: integer;
  SW: PDWORD absolute Source;
  DW: PDWORD absolute Dest;
begin
  // There is no risk of overlapped copy, they are always different zones source and dest
  if (Count and 3) = 0 then begin
    // It is multiple of 4, so copy DWORDS
    for j := 0 to (Count shr 2)-1 do begin
      (DW+j)^:=(SW+J)^;
    end;
  end else begin
    for j := 0 to Pred(Count) do begin
      (Dest+j)^:=(Source+j)^;
    end;
  end;
end;
*)

procedure QuickSort(const Arr: PBYTE; const ALow, AHigh: SizeInt; Stride: LongInt; const SwapBuffer: PBYTE);
var
  Pivot, vL, vR: Integer;
  ps: integer;
begin

  if AHigh - ALow <= 1 then begin // a little bit of time saver
    if ALow < AHigh then
      if CompareNTLMHash(Arr+ALow*Stride, Arr+AHigh*Stride) > 0 then begin
        move((Arr+(ALow*Stride))^,SwapBuffer^,Stride);
        move((Arr+(AHigh*Stride))^,(Arr+(ALow*Stride))^,Stride);
        move(SwapBuffer^,(Arr+(AHigh*Stride))^,Stride);
      end;
    Exit;
  end;

  vL := ALow;
  vR := AHigh;

  Pivot := ALow + Random(AHigh - ALow); // they say random is best

  while vL < vR do begin
    ps:=Pivot * Stride;
    while (vL < Pivot) and (CompareNTLMHash(Arr+vL*Stride, Arr+ps) <= 0) do
      Inc(vL);

    while (vR > Pivot) and (CompareNTLMHash(Arr+vR*Stride, Arr+ps) > 0) do
      Dec(vR);

    if vL<>vR then begin
      move((Arr+(vL*Stride))^,SwapBuffer^,Stride);
      move((Arr+(vR*Stride))^,(Arr+(vL*Stride))^,Stride);
      move(SwapBuffer^,(Arr+(vR*Stride))^,Stride);
    end;

    if Pivot = vL then // swap pivot if we just hit it from one side
      Pivot := vR
    else if Pivot = vR then
      Pivot := vL;
  end;

  if Pivot - 1 >= ALow then
    QuickSort(Arr,ALow, Pivot - 1, Stride, SwapBuffer);
  if Pivot + 1 <= AHigh then
    QuickSort(Arr,Pivot + 1, AHigh, Stride, SwapBuffer);
end;


procedure Tntlmpwnd.SortBlocks(var lTick: QWord);
var
  lCountTotal: Integer;
  lSortTick: QWord;
  lElapsed: QWord;
  lCount: integer;
  j: integer;
  FileStream: TFileStream;
  lBlockBuffer: PBYTE=nil;
  lNeededMemory: integer;
  lAllocatedMemory: integer=0;
  lSwapBuffer: TNTLMHash;
  lSortTime: QWord;
  {$IFDEF VERIFY_SORT}
  lVerifyLoopCounter: integer;
  {$ENDIF}
begin
  lSortTick:=GetTickCount64();
  lCount:=0;
  lCountTotal:=0;
  for j := 0 to BLOCKS-1 do begin
    FileStream:=TFileStream.Create(ConcatPaths([HASHESPATH,format('ntlmblock-%.4d.bin', [j])]), fmOpenRead or fmShareDenyWrite);
    lCount:=FileStream.Size div sizeof(TNTLMHash);
    lNeededMemory:=lCount * sizeof(TNTLMHash);
    if lNeededMemory>lAllocatedMemory then begin
      write('Reallocating memory from ',lAllocatedMemory,' to ');
      lAllocatedMemory:=lNeededMemory + (lNeededMemory div 10); // Allocate a 10% more, it should prevent reallocations
      writeln(lAllocatedMemory);
      lBlockBuffer:=ReAllocMem(lBlockBuffer,lAllocatedMemory);
    end;
    write(format('Read block %d having %.0n hashes...        '#13, [j, double(lCount)]));
    FileStream.Read(lBlockBuffer^, FileStream.Size);
    write(format('Sort block %d having %.0n hashes...        '#13, [j, double(lCount)]));
    FileStream.Free;
    if not KEEP_INTERMEDIATE then begin
      DeleteFile(ConcatPaths([HASHESPATH,format('ntlmblock-%.4d.bin', [j])]));
    end;

    lSortTime:=GetTickCount64;
    QuickSort(lBlockBuffer,0,lCount-1,sizeof(TNTLMHash),@lSwapBuffer);
    lSortTime:=GetTickCount64-lSortTime;

    {$IFDEF VERIFY_SORT}
    for lVerifyLoopCounter := 1 to Pred(lCount) do begin
      if  CompareNTLMHash(lBlockBuffer+((lVerifyLoopCounter-1)*20),lBlockBuffer+(lVerifyLoopCounter*20))>0 then begin
        Raise Exception.Create('KBOOMM!! Sort verification failed.');
      end;
    end;
    {$ENDIF}

    write(format('Write block %d having %.0n hashes...        '#13, [j, double(lCount)]));
    FileStream:=TFileStream.Create(ConcatPaths([HASHESPATH,format('ntlmblock-%.4d-sorted.bin', [j])]), fmCreate or fmShareDenyWrite);
    FileStream.Write(lBlockBuffer^, lCount*sizeof(TNTLMHash));
    FileStream.Free;
    lElapsed:=GetTickCount64-lSortTick;
    lCountTotal:=lCountTotal+lCount;
    writeln(format('Round 2: %.2f%%', [(j+1) / BLOCKS * 100]),' Elapsed: ', format('%.1f s', [lElapsed / 1000]), ' ', format('%.1n', [lCountTotal / (lElapsed / 1000)]), ' h/s',format(' Sort: %.0n h/s',[lCount / (lSortTime/1000)]),'         ');
  end;
  if lAllocatedMemory>0 then begin
    writeln('Free memory for ',lAllocatedMemory,' bytes.');
    Freemem(lBlockBuffer,lAllocatedMemory);
  end;
  lElapsed:=GetTickCount64-lTick;
  writeln;
  writeln('Total Elapsed Time: ', format('%.1f s', [lElapsed / 1000]), ' ', format('Speed: %.1n h/s // Total hashes: %.0n', [lCountTotal / (lElapsed / 1000),double(lCountTotal)]));
end;

procedure Tntlmpwnd.VerifySortedFiles();
var
  rec: TSearchRec;
  c,i: integer;
  lFile: string;
  lFiles: TStringList;
  lLastIndex: integer;
begin
  // First verify that it have the needed files in HASHESPATH and that
  // the amount of files matches the "bits" parameter.

  lFiles:=TStringList.Create;
  try
    c:=FindFirst(ConcatPaths([HASHESPATH,'ntlmblock-*-sorted.bin']),faAnyFile,rec);
    while c=0 do begin
      if (rec.Attr and faDirectory)<>faDirectory then begin
        lFile:=rec.Name;
        lFiles.Add(lFile);
      end;
      c:=FindNext(rec);
    end;
    if lFiles.Count>0 then begin
      lFiles.Sort;
      lLastIndex:=strToint(copy(lFiles[lFiles.Count-1],11,4));
    end else begin
      Raise Exception.CreateFmt('Error: Missing sorted files. None found.',[]);
    end;
    if lLastIndex<>lFiles.Count-1 then begin
      Raise Exception.CreateFmt('Error: Missing sorted files. Expected %d but found %d',[lLastIndex+1,lFiles.Count]);
    end;
    writeln('Sorted files found: ',lFiles.Count);
    // Now check if "bits" matches the amount of files.
    if BLOCKS<>lFiles.Count then begin
      c:=lFiles.Count-1;
      i:=0;
      while c>0 do begin
        if (c and 1)<>1 then begin
          Raise Exception.CreateFmt('Error: Sorted files missing.',[]);
        end;
        inc(i);
        c:=c shr 1;
      end;
      Raise Exception.CreateFmt('Error: %d files don''t match "bits" parameter of %d. Use --bits=%d',[lLastIndex+1,BLOCKS_BITS,i]);
    end;
  finally
    FreeAndNil(lFiles);
  end;
end;

function SplitUserHash(constref aLine: string; var aUser: ShortString; var aHash: ShortString): Boolean;
var
  i,j: integer;
  lLimit: integer;
begin
  Result:=false;
  lLimit:=Length(aLine);
  if lLimit<34 then exit;
  i:=1;
  SetLength(aUser,255);
  while i<=lLimit do begin
    if aLine[i]=':' then begin
      SetLength(aUser,i-1);
      break;
    end;
    aUser[i]:=aLine[i];
    inc(i);
  end;
  inc(i);
  if i=lLimit then begin
    //No hash
    SetLength(aHash,0);
    exit;
  end else if i+31<>lLimit then begin
    writeln('Too short or too large line: "',aLine,'"');
    exit;
  end;
  j:=0;
  SetLength(aHash,255);
  while i<=lLimit do begin
    inc(j);
    aHash[j]:=aLine[i];
    inc(i);
  end;
  SetLength(aHash,j);
  Result:=true;
end;

procedure Tntlmpwnd.CheckUsersProc();
const
  USERS_GROW=753; // nice for counters :-)
var
  F: TFileStream;
  lFilter: TTextStreamFilter;
  lLine: String;
  lUser: ShortString='';
  lHash: ShortString='';
  lUsers: array of TNTLMUsersHash;
  lUsersAllocated: integer=0;
  lUsersIndex: integer=0;
  j: Integer;
  lPrevHash: ShortString;
  lPrevUser: ShortString;
  lCurrentIndex: integer;
  lIndex: integer;
  lEntries: integer;
  lBlocks: array of TNTLMHash;
  lLargestUser: integer;
  lFoundAt: integer;
  lMatchesCounter: integer=0;
  lUsersRepeatedHash: integer=0;
  lTick: QWord;
  lTickPartial: QWORD;
  lElapsed: QWord;
//  kl: integer;
begin
  lTick:=GetTickCount64();
  lTickPartial:=lTick;
  F:=TFileStream.Create(USERSFILE,fmOpenRead or fmShareDenyWrite);
  lFilter:=TTextStreamFilter.Create(F,false);
  try
    while not lFilter.EOF do begin
      lLine:=Trim(lFilter.ReadLn);
      if SplitUserHash(lLine,lUser,lHash) then begin
        if lUsersIndex=lUsersAllocated then begin
          //Allocate a bit more
          inc(lUsersAllocated,USERS_GROW);
          SetLength(lUsers,lUsersAllocated);
          Write(format('Read users: %.0n',[double(lUsersIndex)]),#13);
        end;
        lUsers[lUsersIndex].User:=lUser;
        fastHexToBin(@lHash[1],@lUsers[lUsersIndex].NTML[0],16);
        (*
        // For debug, generate random hashes
        for kl := 0 to Pred(15) do
        begin
          lUsers[lUsersIndex].NTML[kl]:=BYTE(Random(255));
        end;
        *)
        inc(lUsersIndex);
      end;
    end;
    FreeAndNil(lFilter);
    FreeAndNil(F);
    // Adjust array size
    SetLength(lUsers,lUsersIndex);
    Writeln(format('Read users: %.0n',[double(lUsersIndex)]));
    lLargestUser:=0;
    if lUsersIndex>0 then begin
      SortArray(@lUsers[0],lUsersIndex,sizeof(lUsers[0]));
      SetLength(lHash,32);
      SetLength(lPrevHash,32);
      SetLength(lPrevUser,0);
      if lUsersIndex>1 then begin
        writeln('Checking users reusing same password...');
        for j := 0 to Pred(lUsersIndex) do begin
          BinToHex(@lUsers[j].NTML,@lHash[1],16);
          if j>0 then begin
            if lPrevHash=lHash then begin
              inc(lUsersRepeatedHash);
              write('*"',lUsers[j].User,'":',lHash);
              writeln(' same password as "',lPrevUser,'"');
            end;
          end;
          lPrevHash:=lHash;
          lPrevUser:=lUser;
          if Length(lUser)>lLargestUser then begin
            lLargestUser:=Length(lUser);
          end;
        end;
        writeln;
      end;
      writeln('Checking user''s NTLM hash against PWND list...');
      writeln;
      lCurrentIndex:=-1;
      for j := 0 to Pred(lUsersIndex) do begin
        BinToHex(@lUsers[j].NTML,@lHash[1],16);
        lIndex:=GetHexIndex(@lHash[1]);
        if lIndex<lCurrentIndex then begin
          raise exception.Create('KBOOM');
        end;
        if lIndex<>lCurrentIndex then begin
          F:=TFileStream.Create(ConcatPaths([HASHESPATH,format('ntlmblock-%.4d-sorted.bin', [lIndex])]),fmOpenRead or fmShareDenyWrite);
          lEntries:=F.Size div sizeof(TNTLMHash);
          SetLength(lBlocks,0);
          SetLength(lBlocks,lEntries);
          F.Read(lBlocks[0],F.Size);
          FreeAndNil(F);
          lCurrentIndex:=lIndex;
        end;
        lFoundAt:=QuickSearch(@lBlocks[0],0,lEntries-1,sizeof(TNTLMHash),@lUsers[j].NTML);
        if lFoundAt<>-1 then begin
          inc(lMatchesCounter);
          writeln('*"',lUsers[j].User,'":',lHash,' PWND!!! Hits: ',format('%.0n',
            {$IFDEF FPC_BIG_ENDIAN}
            [double(LEtoN(lBlocks[lFoundAt].Repeats))]));
            {$ELSE}
            [double(lBlocks[lFoundAt].Repeats)]));
            {$ENDIF}
          write(format('%.0n / %.0n - %s',[double(j+1),double(lUsersIndex),lUsers[j].User+'           ']),#13);
        end;
        if j mod 873 = 0 then begin // 873 arbitrary number
          lElapsed:=GetTickCount64()-lTickPartial;
          if lElapsed>500 then begin
            write(format('%.0n / %.0n - %s',[double(j+1),double(lUsersIndex),lUsers[j].User+'           ']),#13);
            lTickPartial:=GetTickCount64;
          end;
        end;
      end;
      lElapsed:=GetTickCount64()-lTick;
      writeln;
      writeln(format('%.0n users with the same password.',[double(lUsersRepeatedHash)]));
      writeln(format('%.0n users PWND and %.0n users not found in PWNDList.',[double(lMatchesCounter),double(lUsersIndex-lMatchesCounter)]));
      writeln(format('Checked %.0n users in %.2n secs. @ %.2n users/sec.',[double(lUsersIndex),lElapsed / 1000,lUsersIndex / (lElapsed / 1000)]));
    end;
  finally
    FreeAndNil(lFilter);
    FreeAndNil(F);
  end;
end;

procedure Tntlmpwnd.CheckOnePassword(const aPassword: string);
var
  lHash: string;
  lWarning: Boolean=false;
  lFileName: string;
  lStream: TFileStream=nil;
begin
  lHash:=GetNTLMHashForPassword(aPassword,lWarning);
  if lWarning then begin
    writeln('! Non ASCII password submitted. Hash will be wrong.');
  end;
  lFileName:=GetTempFileName;
  lStream:=TFileStream.Create(lFileName,fmCreate or fmShareDenyWrite);
  try
    lhash:='Checked.Password:'+lHash+#13#10;
    lStream.Write(lHash[1],Length(lHash));
    FreeAndNil(lStream);
    USERSFILE:=lFileName;
    VerifySortedFiles();
    CheckUsersProc();
  finally
    FreeAndNil(lStream);
    DeleteFile(lFileName);
  end;
end;

procedure Tntlmpwnd.DoRun;
var
  ErrorMsg: String;
  lTick: QWord;
  lGenPasswordHash: Boolean=false;
  lWarning: Boolean;
  lHash: string;
  lCheckOnePassword: Boolean=false;
begin

  // quick check parameters
  ErrorMsg:=CheckOptions('hk', 'help pwndlist: userslist: bits: generate-blocks check-users hashes-path: keep-intermediate get-ntlm-hash: check-password:');
  if ErrorMsg<>'' then begin
    ShowException(Exception.Create(ErrorMsg));
    Terminate;
    Exit;
  end;

  // parse parameters
  if HasOption('h', 'help') then begin
    WriteHelp;
    if HasOption('help') then begin
      WriteLongHelp;
    end;
    Terminate;
    Exit;
  end;

  if HasOption('get-ntlm-hash') then begin
    lGenPasswordHash:=true;
    lhash:=GetNTLMHashForPassword(GetOptionValue('get-ntlm-hash'),lWarning);
    if lWarning then begin
      write('! Non ASCII password submitted. Hash will be wrong: ');
    end;
    writeln('"',GetOptionValue('get-ntlm-hash'),'" = "',lhash,'"');
    Terminate(0);
    exit;
  end;

  if HasOption('check-users') then begin
    CheckUsers:=true;
  end;
  if HasOption('generate-blocks') then begin
    GenerateBlocks:=true;
  end;
  if HasOption('hashes-path') then begin
    HASHESPATH:=GetOptionValue('hashes-path');
    if not DirectoryExists(HASHESPATH) then begin
      writeln('Unable to locate hashes path: ',HASHESPATH);
      Terminate(1);
      exit;
    end;
  end;

  if GenerateBlocks and (not HasOption('pwndlist')) then begin
    WriteHelp;
    writeln('Error: "--pwndlist" is a mandatory parameter.');
    Terminate(1);
    exit;
  end;

  if CheckUsers and (not HasOption('userslist')) then begin
    WriteHelp;
    writeln('Error: "--userslist" is a mandatory parameter.');
    Terminate(1);
    exit;
  end;

  if HasOption('check-password') then begin
    lCheckOnePassword:=true;
  end;

  if (not CheckUsers) and (not GenerateBlocks) and (not lGenPasswordHash) and (not lCheckOnePassword) then begin
    WriteHelp;
    writeln('Error: Not generate blocks and no check users... Doing nothing.');
    Terminate(1);
    exit;
  end;

  INPUTFILE:=GetOptionValue('pwndlist');
  USERSFILE:=GetOptionValue('userslist');

  if HasOption('bits') then begin
    BLOCKS_BITS:=StrToInt(GetOptionValue('bits'));
    BLOCKS_BITS_MASK:=(1 shl BLOCKS_BITS)-1;
    BLOCKS:=1 shl BLOCKS_BITS;
  end;

  if HasOption('k','keep-intermediate') then begin
    KEEP_INTERMEDIATE:=true;
  end;

  WriteBanner;
  writeln('Generate blocks: ',GenerateBlocks);
  writeln('Check users: ',CheckUsers);
  writeln('PWND list: ',INPUTFILE);
  writeln('Users list: ',USERSFILE);
  writeln('Hashes path: ',HASHESPATH);
  writeln('Bits slice: ',BLOCKS_BITS);
  if KEEP_INTERMEDIATE then begin
    writeln('Keep intermediate: ',KEEP_INTERMEDIATE);
  end;
  writeln;

  InitializeHexTable();
  lTick:=GetTickCount64();
  if GenerateBlocks then begin
    NTLMPwndGen(lTick);
    SortBlocks(lTick);
  end;
  if CheckUsers then begin
    VerifySortedFiles();
    CheckUsersProc();
  end;
  if lCheckOnePassword then begin
    CheckOnePassword(GetOptionValue('check-password'));
  end;

  // stop program loop
  Terminate;
end;

var
  Application: Tntlmpwnd;

begin
  Application:=Tntlmpwnd.Create(nil);
  Application.Title:='NTLM PWND';
  Application.Run;
  Application.Free;
end.

