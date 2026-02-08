interface Props {
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
}

const gradeConfig = {
  A: { color: "text-green-600", bg: "bg-green-100", ring: "ring-green-500" },
  B: { color: "text-blue-600", bg: "bg-blue-100", ring: "ring-blue-500" },
  C: { color: "text-yellow-600", bg: "bg-yellow-100", ring: "ring-yellow-500" },
  D: { color: "text-orange-600", bg: "bg-orange-100", ring: "ring-orange-500" },
  F: { color: "text-red-600", bg: "bg-red-100", ring: "ring-red-500" },
};

export function SecurityScoreCard({ score, grade }: Props) {
  const config = gradeConfig[grade];

  return (
    <div className="bg-white border rounded-2xl p-6 flex items-center gap-5">
      <div className={`w-16 h-16 rounded-full ${config.bg} ring-4 ${config.ring} flex items-center justify-center`}>
        <span className={`text-2xl font-bold ${config.color}`}>{grade}</span>
      </div>
      <div>
        <div className="text-3xl font-bold">{score}<span className="text-lg text-gray-400">/100</span></div>
        <div className="text-sm text-gray-500">Security Score</div>
      </div>
    </div>
  );
}
