//------------------------------------------------------------------------------
//
//   Copyright 2018-2019 Fetch.AI Limited
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//
//------------------------------------------------------------------------------

#include "math/linalg/blas/base.hpp"
#include "math/linalg/blas/gemm_tn_vector.hpp"
#include "math/linalg/prototype.hpp"
#include "math/tensor/tensor.hpp"

#include "gtest/gtest.h"

using namespace fetch;
using namespace fetch::math;
using namespace fetch::math::linalg;

TEST(blas_gemm_vectorised, blas_gemm_tn_vector1)
{
  Blas<double, Signature(_C <= _alpha, _A, _B, _beta, _C),
       Computes(_C <= _alpha * T(_A) * _B + _beta * _C), platform::Parallelisation::VECTORISE>
      gemm_tn_vector;
  // Computing _C <=  _alpha * T(_A) * _B + _beta * _C
  using Type = double;
  auto alpha = Type(1);
  auto beta  = Type(0);

  Tensor<Type>     tensor_A = Tensor<Type>::FromString(R"(
  	0.3745401188473625 0.9507143064099162 0.7319939418114051;
 0.5986584841970366 0.15601864044243652 0.15599452033620265
  	)");
  TensorView<Type> A        = tensor_A.View();
  Tensor<Type>     tensor_B = Tensor<Type>::FromString(R"(
  	0.05808361216819946 0.8661761457749352 0.6011150117432088;
 0.7080725777960455 0.020584494295802447 0.9699098521619943
  	)");
  TensorView<Type> B        = tensor_B.View();
  Tensor<Type>     tensor_C = Tensor<Type>::FromString(R"(
  	0.8324426408004217 0.21233911067827616 0.18182496720710062;
 0.18340450985343382 0.3042422429595377 0.5247564316322378;
 0.43194501864211576 0.2912291401980419 0.6118528947223795
  	)");
  TensorView<Type> C        = tensor_C.View();
  gemm_tn_vector(alpha, A, B, beta, C);

  Tensor<Type>     ref_tensor_C = Tensor<Type>::FromString(R"(
  0.4456482991294304 0.33674079873438223 0.8057864498423065;
 0.1656934419785827 0.8266976184734581 0.7228126579480724;
 0.15297229436215787 0.6372467595628419 0.591313169085288
  )");
  TensorView<Type> refC         = ref_tensor_C.View();

  ASSERT_TRUE(ref_tensor_C.AllClose(tensor_C));
}

TEST(blas_gemm_vectorised, blas_gemm_tn_vector2)
{
  Blas<double, Signature(_C <= _alpha, _A, _B, _beta, _C),
       Computes(_C <= _alpha * T(_A) * _B + _beta * _C), platform::Parallelisation::VECTORISE>
      gemm_tn_vector;
  // Computing _C <=  _alpha * T(_A) * _B + _beta * _C
  using Type = double;
  auto alpha = Type(0);
  auto beta  = Type(1);

  Tensor<Type>     tensor_A = Tensor<Type>::FromString(R"(
  	0.13949386065204183 0.29214464853521815 0.3663618432936917;
 0.45606998421703593 0.7851759613930136 0.19967378215835974
  	)");
  TensorView<Type> A        = tensor_A.View();
  Tensor<Type>     tensor_B = Tensor<Type>::FromString(R"(
  	0.5142344384136116 0.5924145688620425 0.046450412719997725;
 0.6075448519014384 0.17052412368729153 0.06505159298527952
  	)");
  TensorView<Type> B        = tensor_B.View();
  Tensor<Type>     tensor_C = Tensor<Type>::FromString(R"(
  	0.9488855372533332 0.9656320330745594 0.8083973481164611;
 0.3046137691733707 0.09767211400638387 0.6842330265121569;
 0.4401524937396013 0.12203823484477883 0.4951769101112702
  	)");
  TensorView<Type> C        = tensor_C.View();
  gemm_tn_vector(alpha, A, B, beta, C);

  Tensor<Type>     ref_tensor_C = Tensor<Type>::FromString(R"(
  0.9488855372533332 0.9656320330745594 0.8083973481164611;
 0.3046137691733707 0.09767211400638387 0.6842330265121569;
 0.4401524937396013 0.12203823484477883 0.4951769101112702
  )");
  TensorView<Type> refC         = ref_tensor_C.View();

  ASSERT_TRUE(ref_tensor_C.AllClose(tensor_C));
}

TEST(blas_gemm_vectorised, blas_gemm_tn_vector3)
{
  Blas<double, Signature(_C <= _alpha, _A, _B, _beta, _C),
       Computes(_C <= _alpha * T(_A) * _B + _beta * _C), platform::Parallelisation::VECTORISE>
      gemm_tn_vector;
  // Computing _C <=  _alpha * T(_A) * _B + _beta * _C
  using Type = double;
  auto alpha = Type(1);
  auto beta  = Type(1);

  Tensor<Type>     tensor_A = Tensor<Type>::FromString(R"(
  	0.034388521115218396 0.9093204020787821 0.2587799816000169;
 0.662522284353982 0.31171107608941095 0.5200680211778108
  	)");
  TensorView<Type> A        = tensor_A.View();
  Tensor<Type>     tensor_B = Tensor<Type>::FromString(R"(
  	0.5467102793432796 0.18485445552552704 0.9695846277645586;
 0.7751328233611146 0.9394989415641891 0.8948273504276488
  	)");
  TensorView<Type> B        = tensor_B.View();
  Tensor<Type>     tensor_C = Tensor<Type>::FromString(R"(
  	0.5978999788110851 0.9218742350231168 0.0884925020519195;
 0.1959828624191452 0.045227288910538066 0.32533033076326434;
 0.388677289689482 0.2713490317738959 0.8287375091519293
  	)");
  TensorView<Type> C        = tensor_C.View();
  gemm_tn_vector(alpha, A, B, beta, C);

  Tensor<Type>     ref_tensor_C = Tensor<Type>::FromString(R"(
  1.1302433056071457 1.5506700912834535 0.7146781438045392;
 0.9347351599342958 0.5061714427949007 1.4859210106475778;
 0.9332767593138604 0.8077890198114085 1.545017690717192
  )");
  TensorView<Type> refC         = ref_tensor_C.View();

  ASSERT_TRUE(ref_tensor_C.AllClose(tensor_C));
}

TEST(blas_gemm_vectorised, blas_gemm_tn_vector4)
{
  Blas<double, Signature(_C <= _alpha, _A, _B, _beta, _C),
       Computes(_C <= _alpha * T(_A) * _B + _beta * _C), platform::Parallelisation::VECTORISE>
      gemm_tn_vector;
  // Computing _C <=  _alpha * T(_A) * _B + _beta * _C
  using Type = double;
  auto alpha = Type(0.27568636699969307);
  auto beta  = Type(0.0172033522599756);

  Tensor<Type>     tensor_A = Tensor<Type>::FromString(R"(
  	0.3567533266935893 0.28093450968738076 0.5426960831582485;
 0.14092422497476265 0.8021969807540397 0.07455064367977082
  	)");
  TensorView<Type> A        = tensor_A.View();
  Tensor<Type>     tensor_B = Tensor<Type>::FromString(R"(
  	0.9868869366005173 0.7722447692966574 0.1987156815341724;
 0.005522117123602399 0.8154614284548342 0.7068573438476171
  	)");
  TensorView<Type> B        = tensor_B.View();
  Tensor<Type>     tensor_C = Tensor<Type>::FromString(R"(
  	0.7290071680409873 0.7712703466859457 0.07404465173409036;
 0.3584657285442726 0.11586905952512971 0.8631034258755935;
 0.6232981268275579 0.3308980248526492 0.06355835028602363
  	)");
  TensorView<Type> C        = tensor_C.View();
  gemm_tn_vector(alpha, A, B, beta, C);

  Tensor<Type>     ref_tensor_C = Tensor<Type>::FromString(R"(
  0.10981823842892052 0.12090167536365108 0.04827994182954502;
 0.08382226476534708 0.24214673592130267 0.1865636390929995;
 0.1584883259249804 0.13799096527805804 0.04535180058786325
  )");
  TensorView<Type> refC         = ref_tensor_C.View();

  ASSERT_TRUE(ref_tensor_C.AllClose(tensor_C));
}

TEST(blas_gemm_vectorised, blas_gemm_tn_vector5)
{
  Blas<double, Signature(_C <= _alpha, _A, _B, _beta, _C),
       Computes(_C <= _alpha * T(_A) * _B + _beta * _C), platform::Parallelisation::VECTORISE>
      gemm_tn_vector;
  // Computing _C <=  _alpha * T(_A) * _B + _beta * _C
  using Type = double;
  auto alpha = Type(2.604572696395226);
  auto beta  = Type(2.7718641791184773);

  Tensor<Type>     tensor_A = Tensor<Type>::FromString(R"(
  	0.3109823217156622 0.32518332202674705 0.7296061783380641;
 0.6375574713552131 0.8872127425763265 0.4722149251619493
  	)");
  TensorView<Type> A        = tensor_A.View();
  Tensor<Type>     tensor_B = Tensor<Type>::FromString(R"(
  	0.1195942459383017 0.713244787222995 0.7607850486168974;
 0.5612771975694962 0.770967179954561 0.49379559636439074
  	)");
  TensorView<Type> B        = tensor_B.View();
  Tensor<Type>     tensor_C = Tensor<Type>::FromString(R"(
  	0.5227328293819941 0.42754101835854963 0.02541912674409519;
 0.10789142699330445 0.03142918568673425 0.6364104112637804;
 0.3143559810763267 0.5085706911647028 0.907566473926093
  	)");
  TensorView<Type> C        = tensor_C.View();
  gemm_tn_vector(alpha, A, B, beta, C);

  Tensor<Type>     ref_tensor_C = Tensor<Type>::FromString(R"(
  2.477850029017208 3.0430377867816074 1.5066556232340071;
 1.6973573637610235 2.472768542791682 3.5494683113388006;
 1.788943488653848 3.713303235559065 4.56870835065634
  )");
  TensorView<Type> refC         = ref_tensor_C.View();

  ASSERT_TRUE(ref_tensor_C.AllClose(tensor_C));
}

TEST(blas_gemm_vectorised, blas_gemm_tn_vector6)
{
  Blas<double, Signature(_C <= _alpha, _A, _B, _beta, _C),
       Computes(_C <= _alpha * T(_A) * _B + _beta * _C), platform::Parallelisation::VECTORISE>
      gemm_tn_vector;
  // Computing _C <=  _alpha * T(_A) * _B + _beta * _C
  using Type = double;
  auto alpha = Type(3);
  auto beta  = Type(3);

  Tensor<Type>     tensor_A = Tensor<Type>::FromString(R"(
  	0.24929222914887494 0.41038292303562973 0.7555511385430487;
 0.22879816549162246 0.07697990982879299 0.289751452913768
  	)");
  TensorView<Type> A        = tensor_A.View();
  Tensor<Type>     tensor_B = Tensor<Type>::FromString(R"(
  	0.16122128725400442 0.9296976523425731 0.808120379564417;
 0.6334037565104235 0.8714605901877177 0.8036720768991145
  	)");
  TensorView<Type> B        = tensor_B.View();
  Tensor<Type>     tensor_C = Tensor<Type>::FromString(R"(
  	0.18657005888603584 0.8925589984899778 0.5393422419156507;
 0.8074401551640625 0.8960912999234932 0.3180034749718639;
 0.11005192452767676 0.22793516254194168 0.4271077886262563
  	)");
  TensorView<Type> C        = tensor_C.View();
  gemm_tn_vector(alpha, A, B, beta, C);

  Tensor<Type>     ref_tensor_C = Tensor<Type>::FromString(R"(
  1.1150486714307748 3.9711419490303896 2.7740372088277763;
 2.7670859470329567 4.0341248930495945 2.134526647541353;
 1.2461775311992485 3.54862876330246 3.8116476403012087
  )");
  TensorView<Type> refC         = ref_tensor_C.View();

  ASSERT_TRUE(ref_tensor_C.AllClose(tensor_C));
}

TEST(blas_gemm_vectorised, blas_gemm_tn_vector7)
{
  Blas<double, Signature(_C <= _alpha, _A, _B, _beta, _C),
       Computes(_C <= _alpha * T(_A) * _B + _beta * _C), platform::Parallelisation::VECTORISE>
      gemm_tn_vector;
  // Computing _C <=  _alpha * T(_A) * _B + _beta * _C
  using Type = double;
  auto alpha = Type(1.5238231607380632);
  auto beta  = Type(1.6746586496235456);

  Tensor<Type>     tensor_A = Tensor<Type>::FromString(R"(
  	0.8180147659224931 0.8607305832563434 0.006952130531190703 0.5107473025775657 0.417411003148779;
 0.22210781047073025 0.1198653673336828 0.33761517140362796 0.9429097039125192 0.32320293202075523
  	)");
  TensorView<Type> A        = tensor_A.View();
  Tensor<Type>     tensor_B = Tensor<Type>::FromString(R"(
  	0.5187906217433661 0.7030189588951778 0.363629602379294 0.9717820827209607 0.9624472949421112 0.25178229582536416 0.49724850589238545;
 0.30087830981676966 0.2848404943774676 0.036886947354532795 0.6095643339798968 0.5026790232288615 0.05147875124998935 0.27864646423661144
  	)");
  TensorView<Type> B        = tensor_B.View();
  Tensor<Type>     tensor_C = Tensor<Type>::FromString(R"(
  	0.9082658859666537 0.23956189066697242 0.1448948720912231 0.489452760277563 0.9856504541106007 0.2420552715115004 0.6721355474058786;
 0.7616196153287176 0.23763754399239967 0.7282163486118596 0.3677831327192532 0.6323058305935795 0.6335297107608947 0.5357746840747585;
 0.0902897700544083 0.835302495589238 0.32078006497173583 0.18651851039985423 0.040775141554763916 0.5908929431882418 0.6775643618422824;
 0.016587828927856152 0.512093058299281 0.22649577519793795 0.6451727904094499 0.17436642900499144 0.690937738102466 0.3867353463005374;
 0.9367299887367345 0.13752094414599325 0.3410663510502585 0.11347352124058907 0.9246936182785628 0.877339353380981 0.2579416277151556
  	)");
  TensorView<Type> C        = tensor_C.View();
  gemm_tn_vector(alpha, A, B, beta, C);

  Tensor<Type>     ref_tensor_C = Tensor<Type>::FromString(R"(
  2.2695461145273184 1.3739095737960556 0.7084018294906388 2.2373111262342196 3.020461324422315 0.736632204077098 1.8397315056978862;
 2.01085579082639 1.372069425421178 1.703188363653085 2.0018408822097467 2.413059598148754 1.4005867511581036 1.6003272311331322;
 0.3114921232303335 1.552834901680109 0.5600264096137308 0.6362497322710919 0.3370916091859595 1.0186953718593443 1.2833108602145316;
 0.863858035192818 1.8139993857821843 0.7153120576128107 2.7126099671104162 1.7633290937005068 1.4270102351118858 1.4350194639440406;
 2.0468690335781923 0.8177483823406198 0.8206271345788074 1.1083546057788272 2.4082924125341725 1.6547462201461203 0.8854788679865785
  )");
  TensorView<Type> refC         = ref_tensor_C.View();

  ASSERT_TRUE(ref_tensor_C.AllClose(tensor_C));
}
