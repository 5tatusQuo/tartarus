// @category Tartarus
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class TartarusFunctions extends GhidraScript {
    @Override
    protected void run() throws Exception {
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            String name = function.getName().replace("\t", " ").replace("\n", " ");
            println("TARTARUS\t" + function.getEntryPoint() + "\t" + name);
        }
    }
}
