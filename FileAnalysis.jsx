import React, { useState } from 'react';
import { Upload, FileText, AlertCircle } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Progress } from '@/components/ui/progress';

const FileAnalysis = () => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState(null);

  const handleFileSelect = (event) => {
    const file = event.target.files[0];
    setSelectedFile(file);
    setAnalysis(null);
    setError(null);
  };

  const analyzeFile = async () => {
    if (!selectedFile) return;

    setAnalyzing(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        throw new Error('Analysis failed');
      }

      const result = await response.json();
      //setAnalysis(result);
      setAnalysis(result.data);
    } catch (err) {
      setError(err.message);
    } finally {
      setAnalyzing(false);
    }
  };

  const renderFileInfo = () => (
    <Card className="mb-4">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileText className="w-5 h-5" />
          File Information
        </CardTitle>
      </CardHeader>
      <CardContent>
        {selectedFile && (
          <div className="space-y-2">
            <p><strong>Name:</strong> {selectedFile.name}</p>
            <p><strong>Size:</strong> {(selectedFile.size / 1024).toFixed(2)} KB</p>
            <p><strong>Type:</strong> {selectedFile.type || 'Unknown'}</p>
          </div>
        )}
      </CardContent>
    </Card>
  );

  const renderAnalysisResults = () => {
    if (!analysis) return null;

    const { riskScore, threats, recommendations } = analysis;
    const riskLevel = riskScore > 0.7 ? 'high' : riskScore > 0.4 ? 'medium' : 'low';

    return (
      <Card className="mb-4">
        <CardHeader>
          <CardTitle>Analysis Results</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div>
              <h3 className="text-sm font-medium mb-2">Risk Level</h3>
              <Progress 
                value={riskScore * 100} 
                className={`h-2 ${
                  riskLevel === 'high' ? 'bg-red-500' :
                  riskLevel === 'medium' ? 'bg-yellow-500' : 'bg-green-500'
                }`}
              />
              <p className="text-sm mt-1">
                Risk Score: {(riskScore * 100).toFixed(1)}%
              </p>
            </div>

            {threats.length > 0 && (
              <div>
                <h3 className="text-sm font-medium mb-2">Detected Threats</h3>
                <div className="space-y-2">
                  {threats.map((threat, index) => (
                    <Alert key={index} variant="destructive">
                      <AlertCircle className="w-4 h-4" />
                      <AlertDescription>{threat}</AlertDescription>
                    </Alert>
                  ))}
                </div>
              </div>
            )}

            {recommendations.length > 0 && (
              <div>
                <h3 className="text-sm font-medium mb-2">Recommendations</h3>
                <ul className="list-disc pl-4 space-y-1">
                  {recommendations.map((rec, index) => (
                    <li key={index} className="text-sm">{rec}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    );
  };

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <h1 className="text-3xl font-bold mb-6">File Analysis</h1>
      
      <Card className="mb-6">
        <CardContent className="pt-6">
          <div className="flex items-center justify-center w-full">
            <label className="flex flex-col items-center justify-center w-full h-32 border-2 border-dashed rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800">
              <div className="flex flex-col items-center justify-center pt-5 pb-6">
                <Upload className="w-8 h-8 mb-2" />
                <p className="mb-2 text-sm text-gray-500 dark:text-gray-400">
                  Click to upload or drag and drop
                </p>
              </div>
              <input
                type="file"
                className="hidden"
                onChange={handleFileSelect}
              />
            </label>
          </div>
          
          {selectedFile && (
            <div className="mt-4 flex justify-center">
              <button
                onClick={analyzeFile}
                disabled={analyzing}
                className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:opacity-50"
              >
                {analyzing ? 'Analyzing...' : 'Analyze File'}
              </button>
            </div>
          )}
        </CardContent>
      </Card>

      {error && (
        <Alert variant="destructive" className="mb-4">
          <AlertCircle className="w-4 h-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {selectedFile && renderFileInfo()}
      {analysis && renderAnalysisResults()}
    </div>
  );
};

export default FileAnalysis;