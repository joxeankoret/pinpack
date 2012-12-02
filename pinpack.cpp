#include "pin.H"

#include <iostream>
#include <fstream>
#include <algorithm>
#include <deque>
#include <map>

//--------------------------------------------------------------------------
// Global variables 

struct segdata_t
{
  size_t  size;
  ADDRINT check;
  bool    written;
};

typedef std::map<ADDRINT, segdata_t> segmap_t;
segmap_t seg_bytes;

typedef std::deque<ADDRINT> addrdeq_t;
addrdeq_t write_address;

ADDRINT min_ea=0;
ADDRINT max_ea=-1;

//--------------------------------------------------------------------------
// Command line switches
KNOB<string> knob_output_file(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "", "specify output filename");

//--------------------------------------------------------------------------
// Utilities

//--------------------------------------------------------------------------
INT32 Usage()
{
  cerr << "This tool unpacks Skype" << endl;
  cerr << KNOB_BASE::StringKnobSummary() << endl;

  return -1;
}

//--------------------------------------------------------------------------
// Analysis routines

//--------------------------------------------------------------------------
// Handle memory write records
VOID record_mem_write_cb(VOID * ip, VOID * addr)
{
  ADDRINT ea = (ADDRINT)addr;
  segmap_t::iterator p;
  for ( p = seg_bytes.begin(); p != seg_bytes.end() && !p->second.written; ++p )
  {
    ADDRINT start_ea = p->first;
    if ( ea >= start_ea )
    {
      segdata_t *seg = &p->second;
      if ( ea <= start_ea+seg->size )
      {
        fprintf(stderr, "%p: W %p\n", ip, addr);
        write_address.push_back((ADDRINT)addr);
        seg->written = true;
        break;
      }
    }
  }
}

//--------------------------------------------------------------------------
VOID check_unpacked_cb(VOID * ip, const CONTEXT *ctxt, THREADID tid)
{
  ADDRINT ea = (ADDRINT)ip;
  addrdeq_t::iterator it = std::find(write_address.begin(), write_address.end(), ea);
  if ( it != write_address.end() )
    write_address.erase(it);
  fprintf(stderr, "Layer unpacked: %p\n", ip);
  PIN_ApplicationBreakpoint(ctxt, tid, false, "Layer unpacked!");
}

//--------------------------------------------------------------------------
inline ADDRINT was_writen(ADDRINT ea)
{
  return std::find(write_address.begin(), write_address.end(), ea) != write_address.end();
}

//--------------------------------------------------------------------------
inline ADDRINT valid_ea(ADDRINT ea)
{
  if ( ea < min_ea || ea > max_ea )
    return 0;
  return 1;
}

//--------------------------------------------------------------------------
// Instrumentation callbacks

//--------------------------------------------------------------------------
static VOID trace_cb(TRACE trace, VOID *v)
{
  // Visit every basic block in the trace
  for ( BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl) )
  {
    for( INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins=INS_Next(ins) )
    {
      ADDRINT ea = INS_Address(ins);
      if ( !valid_ea(ea) )
        continue;

      if ( was_writen(ea) )
      {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)check_unpacked_cb,
            IARG_INST_PTR,
            IARG_CONST_CONTEXT,
            IARG_THREAD_ID,
            IARG_END);
      }

      // Instruments memory accesses using a predicated call, i.e.
      // the instrumentation is called iff the instruction will actually be executed.
      //
      // The IA-64 architecture has explicitly predicated instructions. 
      // On the IA-32 and Intel(R) 64 architectures conditional moves and REP 
      // prefixed instructions appear as predicated instructions in Pin.
      UINT32 mem_operands = INS_MemoryOperandCount(ins);

      // Iterate over each memory operand of the instruction.
      for ( UINT32 mem_op = 0; mem_op < mem_operands; mem_op++ )
      {
        // Note that in some architectures a single memory operand can be 
        // both read and written (for instance incl (%eax) on IA-32)
        // In that case we instrument it once for read and once for write.
        if ( INS_MemoryOperandIsWritten(ins, mem_op) )
        {
          INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)valid_ea,
            IARG_MEMORYOP_EA,
            mem_op, 
            IARG_END);

          INS_InsertThenPredicatedCall(
              ins, IPOINT_BEFORE, (AFUNPTR)record_mem_write_cb,
              IARG_INST_PTR,
              IARG_MEMORYOP_EA, mem_op,
              IARG_END);
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
static VOID app_start_cb(VOID *v)
{
  IMG img = APP_ImgHead();
  for( SEC sec= IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) )
  {
    ADDRINT sec_ea = SEC_Address(sec);
    if ( sec_ea != 0 )
    {
      ADDRINT check;
      size_t bytes = PIN_SafeCopy(&check, (void*)sec_ea, sizeof(ADDRINT));
      if ( bytes == sizeof(ADDRINT) )
      {
        if ( min_ea > sec_ea || min_ea == 0 )
          min_ea = sec_ea;
        if ( max_ea < sec_ea || max_ea == (unsigned)-1 )
          max_ea = sec_ea;

        segdata_t seg;
        seg.size = SEC_Size(sec);
        seg.check = check;
        seg.written = false;
        seg_bytes[sec_ea] = seg;
        //cerr << "Monitoring segment " << SEC_Name(sec) << " " << hexstr(sec_ea)
        //     << ":" << hexstr(sec_ea+SEC_Size(sec)) << endl;
      }
    }
  }
}

//--------------------------------------------------------------------------
static VOID fini_cb(INT32 code, VOID *v)
{
  ;
}

//--------------------------------------------------------------------------
int main(int argc, char *argv[])
{
  // Initialize PIN library. Print help message if -h(elp) is specified
  // in the command line or the command line is invalid 
  if( PIN_Init(argc,argv) )
    return Usage();

  // Register function to be called to instrument traces
  TRACE_AddInstrumentFunction(trace_cb, 0);

  // Register function to be called at application start time
  PIN_AddApplicationStartFunction(app_start_cb, 0);

  // Register function to be called when the application exits
  PIN_AddFiniFunction(fini_cb, 0);

  // Start the program, never returns
  PIN_StartProgram();
  
  return 0;
}
