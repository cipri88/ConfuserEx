using System;
using System.CodeDom;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Confuser.Core;
using Confuser.Core.Services;
using Confuser.DynCipher;
using Confuser.LocalVirtualization;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;
using dnlib.DotNet.Writer;
using dnlib.Threading;

namespace Confuser.Protections.LocalVirtualization
{
	internal class LocalVirtualiztionPhase : ProtectionPhase {
		static readonly JumpMangler Jump = new JumpMangler();
		static readonly SwitchMangler Switch = new SwitchMangler();

        static readonly string VPC_VO = "vpc_vo";
        static readonly string OPCODE_VO = "opcode_vo";
        static readonly string DATA_VO = "data_vo";

	    private Dictionary<int, Instruction> dataInstructions;
        private Dictionary<int, Instruction> dataFiltered;

		public LocalVirtualiztionPhase(LocalVirtualizationProtection parent)
			: base(parent) { }

		public override ProtectionTargets Targets {
			get { return ProtectionTargets.Methods; }
		}

		public override string Name {
			get { return "Local Virtualization mangling"; }
		}

		CFContext ParseParameters(MethodDef method, ConfuserContext context, ProtectionParameters parameters, RandomGenerator random, bool disableOpti) {
			var ret = new CFContext();
			ret.Type = parameters.GetParameter(context, method, "type", CFType.Switch);
			ret.Predicate = parameters.GetParameter(context, method, "predicate", PredicateType.Normal);

			int rawIntensity = parameters.GetParameter(context, method, "intensity", 60);
			ret.Intensity = rawIntensity / 100.0;
			ret.Depth = parameters.GetParameter(context, method, "depth", 4);

			ret.JunkCode = parameters.GetParameter(context, method, "junk", false) && !disableOpti;

			ret.Protection = (LocalVirtualizationProtection)Parent;
			ret.Random = random;
			ret.Method = method;
			ret.Context = context;
			ret.DynCipher = context.Registry.GetService<IDynCipherService>();

			if (ret.Predicate == PredicateType.x86) {
				if ((context.CurrentModule.Cor20HeaderFlags & ComImageFlags.ILOnly) != 0)
					context.CurrentModuleWriterOptions.Cor20HeaderOptions.Flags &= ~ComImageFlags.ILOnly;
			}

			return ret;
		}

		static bool DisabledOptimization(ModuleDef module) {
			bool disableOpti = false;
			CustomAttribute debugAttr = module.Assembly.CustomAttributes.Find("System.Diagnostics.DebuggableAttribute");
			if (debugAttr != null) {
				if (debugAttr.ConstructorArguments.Count == 1)
					disableOpti |= ((DebuggableAttribute.DebuggingModes)(int)debugAttr.ConstructorArguments[0].Value & DebuggableAttribute.DebuggingModes.DisableOptimizations) != 0;
				else
					disableOpti |= (bool)debugAttr.ConstructorArguments[1].Value;
			}
			debugAttr = module.CustomAttributes.Find("System.Diagnostics.DebuggableAttribute");
			if (debugAttr != null) {
				if (debugAttr.ConstructorArguments.Count == 1)
					disableOpti |= ((DebuggableAttribute.DebuggingModes)(int)debugAttr.ConstructorArguments[0].Value & DebuggableAttribute.DebuggingModes.DisableOptimizations) != 0;
				else
					disableOpti |= (bool)debugAttr.ConstructorArguments[1].Value;
			}
			return disableOpti;
		}

		protected override void Execute(ConfuserContext context, ProtectionParameters parameters) {
			bool disabledOpti = DisabledOptimization(context.CurrentModule);
			RandomGenerator random = context.Registry.GetService<IRandomService>().GetRandomGenerator(LocalVirtualizationProtection._FullId);

			foreach (MethodDef method in parameters.Targets.OfType<MethodDef>().WithProgress(context.Logger))
				if (method.HasBody && method.Body.Instructions.Count > 0) {
					ProcessMethod(method.Body, ParseParameters(method, context, parameters, random, disabledOpti));
					context.CheckCancellation();
				}
		}

		static ManglerBase GetMangler(CFType type) {
			if (type == CFType.Switch)
				return Switch;
			return Jump;
		}

        	    

        private int InitVirtualProgramCounter(CilBody body, CFContext ctx, int insertIndex)
        {
            //add local variable
            Local vpcVariable = new Local(ctx.Context.CurrentModule.CorLibTypes.UInt32);
            vpcVariable.Name = VPC_VO;
            body.Variables.Locals.Add(vpcVariable);        

            //init vpc
            body.Instructions.Insert(insertIndex+0, Instruction.CreateLdcI4(-1));
            body.Instructions.Insert(insertIndex+1, OpCodes.Stloc.ToInstruction(vpcVariable));

            body.Instructions.Insert(insertIndex + 2, OpCodes.Ldloc.ToInstruction(vpcVariable));
            body.Instructions.Insert(insertIndex + 3, OpCodes.Pop.ToInstruction());

            int instructionsInserted = 4;
            return instructionsInserted;
        }

        private int InitVirtualizationData(CilBody body, CFContext ctx, int insertIndex)
        {
            // Create an int[]           
            SZArraySig objArray = new SZArraySig(ctx.Context.CurrentModule.CorLibTypes.Object);
            Local virtData = new Local(objArray);
            virtData.Name = DATA_VO;
            body.Variables.Locals.Add(virtData);
            
            int initialIndex = insertIndex;
            int opCodeSize = 200;
            body.Instructions.Insert(insertIndex++, Instruction.CreateLdcI4(opCodeSize));
            body.Instructions.Insert(insertIndex++, Instruction.Create(OpCodes.Newarr, ctx.Context.CurrentModule.CorLibTypes.Object));
            body.Instructions.Insert(insertIndex++, OpCodes.Stloc.ToInstruction(virtData));

            //add dummy data
//            body.Instructions.Insert(insertIndex++, OpCodes.Ldloc.ToInstruction(virtData));
//            body.Instructions.Insert(insertIndex++, Instruction.CreateLdcI4(0)); //index
//            body.Instructions.Insert(insertIndex++, Instruction.CreateLdcI4(opCodeSize+2)); //value
//            body.Instructions.Insert(insertIndex++, Instruction.Create(OpCodes.Stelem_I4));

            int instructionsInserted = insertIndex - initialIndex;
            return instructionsInserted;
        }

        private int initVirtualizationOpcode(CilBody body, CFContext ctx, int insertIndex)
        {
            // Create an int[]
            SZArraySig intArray = new SZArraySig(ctx.Context.CurrentModule.CorLibTypes.UInt32);
            Local opCode = new Local(intArray);
            opCode.Name = OPCODE_VO;
            body.Variables.Locals.Add(opCode);

            int initialIndex = insertIndex;
            int opCodeSize = 100;
            body.Instructions.Insert(insertIndex++, Instruction.CreateLdcI4(opCodeSize));
            body.Instructions.Insert(insertIndex++, Instruction.Create(OpCodes.Newarr, ctx.Context.CurrentModule.CorLibTypes.UInt32));
            body.Instructions.Insert(insertIndex++, OpCodes.Stloc.ToInstruction(opCode));

//            body.Instructions.Insert(insertIndex++, OpCodes.Ldloc.ToInstruction(opCode));
//            body.Instructions.Insert(insertIndex++, Instruction.CreateLdcI4(0)); //index
//            body.Instructions.Insert(insertIndex++, Instruction.CreateLdcI4(opCodeSize+1)); //value
//            body.Instructions.Insert(insertIndex++, Instruction.Create(OpCodes.Stelem_I4));

            int instructionsInserted = insertIndex - initialIndex;            
            return instructionsInserted;
        }


        private Dictionary<int, Instruction> initVirtualizationData(CilBody body, CFContext ctx)
	    {
            Dictionary<int, Instruction> variables  = new Dictionary<int, Instruction>();
            Dictionary<int, Instruction> equivalentInstructions = new Dictionary<int, Instruction>();
	        int position = 0;
	        int instructionIndex = 0;
	        foreach(var instr in body.Instructions)
	        {
	            if(!filterInstruction(instr))
                    continue;

                var instructionExists = equivalentInstructions.Where(_ => (instr.Equivalent(_.Value)));	            
                if (!instructionExists.Any())
	            {
                    equivalentInstructions.Add(instructionIndex, instr);
                    instructionIndex++;
	            }
                variables.Add(position++, instr);
	            
	        }

            Debug.WriteLine("variables: "+ variables.Count);
            dataInstructions = variables;
            dataFiltered = equivalentInstructions;

            PopulateVirtualizationData(body, ctx);
            replaceInstruction(body, ctx);

            return variables;
	    }

        private void PopulateVirtualizationData(CilBody body, CFContext ctx)
        {
            int insertIndex = 0;
            Local virtData = body.Variables.Locals.FirstOrDefault(_ => DATA_VO.Equals(_.Name));            
                       
            foreach (var pair in dataFiltered)
            {
                var instr = pair.Value;
                int virtDataIndex = pair.Key;
                body.Instructions.Insert(insertIndex++, OpCodes.Ldloc.ToInstruction(virtData));
                body.Instructions.Insert(insertIndex++, Instruction.CreateLdcI4(virtDataIndex)); //index                
                body.Instructions.Insert(insertIndex++, instr); //value
                body.Instructions.Insert(insertIndex++, Instruction.Create(OpCodes.Stelem_Ref));                
            }
        }

	    private bool filterInstruction(Instruction instruction)
	    {
	        if (instruction.OpCode.isLoadString())
                return true;
	        //if (instruction.OpCode.isLoadConstant())
	            //return true;
	        return false;
	    }

        private void replaceInstruction(CilBody body, CFContext ctx)
        {
            Local virtData = body.Variables.Locals.FirstOrDefault(_ => DATA_VO.Equals(_.Name));
            var instructionList = body.Instructions;
            foreach (var pair in dataInstructions)
            {
                int position = instructionList.IndexOf(pair.Value) + 1;
                instructionList.Insert(position++,Instruction.Create(OpCodes.Pop));

                instructionList.Insert(position++, OpCodes.Ldloc.ToInstruction(virtData));
                var filteredPair = dataFiltered.FirstOrDefault(_ => pair.Value.Equivalent(_.Value));
                var dataKey = filteredPair.Key;
                instructionList.Insert(position++, OpCodes.Ldc_I4.ToInstruction(dataKey));
                instructionList.Insert(position++, Instruction.Create(OpCodes.Ldelem_Ref));
            }
	    }

		void ProcessMethod(CilBody body, CFContext ctx) {
			uint maxStack;
            int instructionsInserted = 0;

            instructionsInserted += initVirtualizationOpcode(body, ctx, instructionsInserted);
            instructionsInserted += InitVirtualizationData(body, ctx, instructionsInserted);

            initVirtualizationData(body, ctx);

            instructionsInserted += InitVirtualProgramCounter(body, ctx, instructionsInserted);
            

//			if (!MaxStackCalculator.GetMaxStack(body.Instructions, body.ExceptionHandlers, out maxStack)) {
//				ctx.Context.Logger.Error("Failed to calcuate maxstack.");
//				throw new ConfuserException(null);
//			}
			//body.MaxStack = (ushort)maxStack;
            body.MaxStack = 8;
			ScopeBlock root = BlockParser.ParseBody(body);

			//GetMangler(ctx.Type).Mangle(body, root, ctx);

			body.Instructions.Clear();
			root.ToBody(body);
			foreach (ExceptionHandler eh in body.ExceptionHandlers) {
				var index = body.Instructions.IndexOf(eh.TryEnd) + 1;
				eh.TryEnd = index < body.Instructions.Count ? body.Instructions[index] : null;
				index = body.Instructions.IndexOf(eh.HandlerEnd) + 1;
				eh.HandlerEnd = index < body.Instructions.Count ? body.Instructions[index] : null;
			}
			body.KeepOldMaxStack = true;
		}
	}
}