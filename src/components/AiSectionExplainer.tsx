import React, { useState } from 'react';
import { MaterialIcon } from './Primitives';
import {
  SECTION_THREAT_EXPLAINERS,
  askAiPlainQuestion,
  type PlainThreatExplanation,
} from '../services/geminiService';

interface AiSectionExplainerProps {
  sectionKey: string;
  onExecuteRecommendedAction?: () => void;
  customActionLabel?: string;
  className?: string;
  defaultExpanded?: boolean;
}

export const AiSectionExplainer: React.FC<AiSectionExplainerProps> = ({
  sectionKey,
  onExecuteRecommendedAction,
  customActionLabel,
  className = '',
  defaultExpanded = false,
}) => {
  const [isOpen, setIsOpen] = useState(defaultExpanded);
  const [userQuery, setUserQuery] = useState('');
  const [aiAnswer, setAiAnswer] = useState<string | null>(null);
  const [asking, setAsking] = useState(false);
  const [actionDoneMsg, setActionDoneMsg] = useState<string | null>(null);

  const explainer: PlainThreatExplanation =
    SECTION_THREAT_EXPLAINERS[sectionKey] || {
      topic: 'Security Sentinel',
      simpleExplanation:
        'This section continuously monitors your computer and protects it against unauthorized changes and attacks.',
      threatOrigin:
        'Threats come from untrusted web downloads, malicious background scripts, and local network probes.',
      threatImpact:
        'If ignored, unauthorized users or malicious code could access your private files or slow down your system.',
      recommendedAction:
        'Review the findings on this screen and use the recommended safe action to protect your workstation.',
      actionButtonLabel: 'Apply Recommended Protection',
      suggestedQuestions: [
        'What does this screen do in simple terms?',
        'Where do threats come from here?',
        'What is the safest action I can take?',
      ],
    };

  const handleAsk = async (questionToAsk?: string) => {
    const q = questionToAsk || userQuery;
    if (!q.trim()) return;
    setAsking(true);
    setAiAnswer(null);
    try {
      const answer = await askAiPlainQuestion(q, explainer.topic);
      setAiAnswer(answer);
    } catch {
      setAiAnswer(
        'Unable to reach Gemini right now. In short: keep this protection enabled, review alerts, and apply the recommended actions.',
      );
    } finally {
      setAsking(false);
    }
  };

  const handleRunAction = () => {
    if (onExecuteRecommendedAction) {
      onExecuteRecommendedAction();
      setActionDoneMsg('Recommended action executed successfully!');
      window.setTimeout(() => setActionDoneMsg(null), 3500);
    }
  };

  return (
    <div
      className={`rounded-xl border transition-all duration-300 shadow-sm overflow-hidden ${
        isOpen
          ? 'bg-gradient-to-b from-[#232034] via-[#1c192b] to-[#161424] border-primary/50 shadow-lg ring-1 ring-primary/20'
          : 'bg-surface-container/70 hover:bg-surface-container/90 border-[#363243]'
      } ${className}`}
    >
      {/* Interactive Header Toggle Button */}
      <div className="flex items-center justify-between p-3.5 px-4 cursor-pointer gap-3" onClick={() => setIsOpen(!isOpen)}>
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-primary-container/20 text-primary border border-primary/30 shrink-0">
            <MaterialIcon name="auto_awesome" className="text-[19px] text-primary animate-pulse" />
          </div>
          <div className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-2.5">
            <span className="font-title-sm text-title-sm text-on-surface font-semibold flex items-center gap-2">
              <span>AI: Explain This & Recommend Action</span>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-code-sm bg-primary/15 text-primary border border-primary/30 font-medium">
                Plain English
              </span>
            </span>
            <span className="font-code-sm text-[12px] text-outline hidden md:inline">
              — Where the threat comes from & how to handle it
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              setIsOpen(!isOpen);
            }}
            className="px-3 py-1.5 rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface text-label-md font-medium flex items-center gap-1.5 transition-all active:scale-95 border border-[#443e54]"
          >
            <span>{isOpen ? 'Collapse' : 'Explain & Guide Me'}</span>
            <MaterialIcon
              name={isOpen ? 'keyboard_arrow_up' : 'keyboard_arrow_down'}
              className="text-[18px] text-primary"
            />
          </button>
        </div>
      </div>

      {/* Expanded Plain-English Breakdown & Guide */}
      {isOpen && (
        <div className="px-5 pb-5 pt-1 border-t border-white/5 flex flex-col gap-4 animate-in fade-in duration-200">
          {actionDoneMsg && (
            <div className="p-3 rounded-lg bg-tertiary-container/30 border border-tertiary/40 text-tertiary font-label-md flex items-center gap-2">
              <MaterialIcon name="check_circle" className="text-tertiary text-[18px]" />
              <span>{actionDoneMsg}</span>
            </div>
          )}

          {/* Three-Card Grid: Plain Explanation, Where Threat Comes From, How to Handle It */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5 mt-2">
            {/* Card 1: Plain English Summary */}
            <div className="flex flex-col p-4 rounded-xl bg-surface-container-low/90 border border-white/5 shadow-sm">
              <div className="flex items-center gap-2 text-primary mb-2">
                <MaterialIcon name="info" className="text-[18px]" />
                <span className="font-title-sm text-[13px] font-bold tracking-wide uppercase">
                  1. What This Is
                </span>
              </div>
              <p className="font-body-md text-[13px] text-on-surface/90 leading-relaxed">
                {explainer.simpleExplanation}
              </p>
            </div>

            {/* Card 2: Where the Threat Comes From */}
            <div className="flex flex-col p-4 rounded-xl bg-surface-container-low/90 border border-error/20 shadow-sm relative overflow-hidden">
              <div className="flex items-center gap-2 text-error mb-2">
                <MaterialIcon name="warning" className="text-[18px]" />
                <span className="font-title-sm text-[13px] font-bold tracking-wide uppercase">
                  2. Where Threat Comes From
                </span>
              </div>
              <p className="font-body-md text-[13px] text-on-surface/90 leading-relaxed mb-2">
                {explainer.threatOrigin}
              </p>
              <div className="mt-auto pt-2 border-t border-white/5 text-[11px] font-code-sm text-error/90 flex items-start gap-1.5">
                <MaterialIcon name="crisis_alert" className="text-[14px] shrink-0 mt-0.5" />
                <span><strong>Impact:</strong> {explainer.threatImpact}</span>
              </div>
            </div>

            {/* Card 3: How to Handle It & Recommended Action */}
            <div className="flex flex-col p-4 rounded-xl bg-surface-container-low/90 border border-tertiary/25 shadow-sm justify-between">
              <div>
                <div className="flex items-center gap-2 text-tertiary mb-2">
                  <MaterialIcon name="verified_user" className="text-[18px]" />
                  <span className="font-title-sm text-[13px] font-bold tracking-wide uppercase">
                    3. How to Handle It
                  </span>
                </div>
                <p className="font-body-md text-[13px] text-on-surface/90 leading-relaxed">
                  {explainer.recommendedAction}
                </p>
              </div>

              {onExecuteRecommendedAction && (
                <div className="mt-3.5 pt-2 border-t border-white/5">
                  <button
                    type="button"
                    onClick={handleRunAction}
                    className="w-full py-2.5 px-3 rounded-lg bg-gradient-to-r from-primary to-primary-container text-white font-title-sm text-[13px] font-semibold flex items-center justify-center gap-2 shadow-md hover:brightness-110 active:scale-98 transition-all"
                  >
                    <MaterialIcon name="play_arrow" className="text-[18px]" />
                    <span>
                      {customActionLabel || explainer.actionButtonLabel || 'Run Recommended Action'}
                    </span>
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Interactive Plain-English Q&A Section */}
          <div className="flex flex-col p-3.5 rounded-xl bg-surface-container-lowest/80 border border-[#363243] gap-2.5">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <span className="font-label-md text-[12px] text-on-surface-variant font-semibold flex items-center gap-1.5">
                <MaterialIcon name="psychology" className="text-secondary text-[16px]" />
                <span>Ask Gemini about this section in plain words:</span>
              </span>
              <div className="flex items-center gap-1.5 flex-wrap">
                {explainer.suggestedQuestions.map((sq, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => {
                      setUserQuery(sq);
                      handleAsk(sq);
                    }}
                    className="text-[11px] font-code-sm px-2.5 py-1 rounded-full bg-surface-container-high hover:bg-surface-bright text-on-surface border border-white/5 transition-all hover:border-primary/40 text-left"
                  >
                    "{sq}"
                  </button>
                ))}
              </div>
            </div>

            <div className="flex items-center gap-2">
              <input
                type="text"
                value={userQuery}
                onChange={(e) => setUserQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleAsk()}
                placeholder="Type any question in plain English (e.g., 'Will this break my internet connection?')..."
                className="flex-1 bg-surface-container-high/90 border border-[#443e54] rounded-lg px-3 py-2 text-on-surface text-[13px] focus:outline-none focus:ring-1 focus:ring-primary font-body-md"
              />
              <button
                type="button"
                disabled={asking || !userQuery.trim()}
                onClick={() => handleAsk()}
                className="px-4 py-2 rounded-lg bg-primary hover:bg-primary-container disabled:opacity-50 text-white font-title-sm text-[12px] font-medium flex items-center gap-1.5 shrink-0 transition-all shadow-sm"
              >
                {asking ? (
                  <>
                    <MaterialIcon name="sync" className="text-[16px] animate-spin" />
                    <span>Thinking...</span>
                  </>
                ) : (
                  <>
                    <MaterialIcon name="send" className="text-[16px]" />
                    <span>Ask AI</span>
                  </>
                )}
              </button>
            </div>

            {aiAnswer && (
              <div className="p-3.5 rounded-lg bg-primary/10 border border-primary/30 text-on-surface text-[13px] leading-relaxed flex items-start gap-2.5 mt-1 animate-in fade-in">
                <MaterialIcon name="auto_awesome" className="text-primary text-[18px] shrink-0 mt-0.5" />
                <div className="flex flex-col gap-1">
                  <span className="font-semibold text-primary text-[12px] uppercase font-code-sm">
                    Gemini Plain-English Guidance:
                  </span>
                  <p className="text-on-surface/95">{aiAnswer}</p>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
