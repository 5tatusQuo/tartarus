// @category Tartarus
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class TartarusDisassembly extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("one function name required");
        Function function = getFunction(args[0]);
        InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
        int count = 0;
        while (instructions.hasNext() && count++ < 10000) {
            Instruction instruction = instructions.next();
            println(instruction.getAddress() + "\t" + instruction.toString());
        }
    }

    private Function getFunction(String name) {
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (function.getName().equals(name)) return function;
        }
        throw new IllegalArgumentException("function not found");
    }
}
