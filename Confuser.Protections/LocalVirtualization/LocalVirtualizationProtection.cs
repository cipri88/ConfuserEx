using System;
using Confuser.Core;
using Confuser.Protections.ControlFlow;
using Confuser.Protections.LocalVirtualization;
using dnlib.DotNet;

namespace Confuser.LocalVirtualization {
	public interface ILocalVirtualizationService {
		void ExcludeMethod(ConfuserContext context, MethodDef method);
	}

    internal class LocalVirtualizationProtection : Protection, ILocalVirtualizationService
    {
		public const string _Id = "local virt";
		public const string _FullId = "Ki.LocalVirtualization";
		public const string _ServiceId = "Ki.LocalVirtualization";

		public override string Name {
			get { return "Local Virtualization Protection"; }
		}

		public override string Description {
			get { return "This protection mangles the code in the methods so control flow and data are obfuscated."; }
		}

		public override string Id {
			get { return _Id; }
		}

		public override string FullId {
			get { return _FullId; }
		}

		public override ProtectionPreset Preset {
			get { return ProtectionPreset.Normal; }
		}

		public void ExcludeMethod(ConfuserContext context, MethodDef method) {
			ProtectionParameters.GetParameters(context, method).Remove(this);
		}

		protected override void Initialize(ConfuserContext context) {
            context.Registry.RegisterService(_ServiceId, typeof(ILocalVirtualizationService), this);
		}

		protected override void PopulatePipeline(ProtectionPipeline pipeline) {
			pipeline.InsertPreStage(PipelineStage.OptimizeMethods, new LocalVirtualiztionPhase(this));
		}
	}
}
